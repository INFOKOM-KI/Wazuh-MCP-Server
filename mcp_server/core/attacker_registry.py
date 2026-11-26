#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
In-memory + JSONL-persistent attacker-IOC registry.
Values registered here are treated as confirmed/suspected attacker indicators
and are EXEMPTED from shape-based masking in the redaction pipeline (never from
Layer 1 credential stripping - credentials stay masked everywhere).

Populated by:
- 3-Sum Engine A trigger IPs (source="engine_a") - automated
- Threat-intel enrichment lookups (source="enrichment") - automated
- True-positive investigation verdicts (source="verdict") - analyst decision
A lookup returns the registering source, so a caller can tell an automated lead
from an analyst-confirmed indicator (ANALYST_SOURCES).

Persistence (BLUETEAM_ATTACKER_REGISTRY=path, optional):
  - JSONL entries {"ioc", "ts", "source", "evidence"}. Each write is a
    read-merge-replace transaction under ``fcntl.flock`` on
    ``<path>.lock``, so two processes cannot lose each other's registrations.
  - TTL: BLUETEAM_ATTACKER_REGISTRY_TTL seconds (default 7d, 0 = never expire);
    expired entries are skipped on lookup and pruned on flush.
  - Cap: BLUETEAM_ATTACKER_REGISTRY_MAX entries (default 10000); oldest evicted.
"""
from __future__ import annotations
import contextlib, ipaddress, json, logging, os, threading, time
from pathlib import Path

try:
    import fcntl
except ImportError:  # non-POSIX: single-writer assumption, see SECURITY.md
    fcntl = None

logger = logging.getLogger("blue_team_mcp.attacker_registry")

_REGISTRY_PATH = os.environ.get("BLUETEAM_ATTACKER_REGISTRY", "")
_REGISTRY_TTL = int(os.environ.get("BLUETEAM_ATTACKER_REGISTRY_TTL", "604800"))
_REGISTRY_MAX = int(os.environ.get("BLUETEAM_ATTACKER_REGISTRY_MAX", "10000"))

# {ioc: {"ts": float, "source": str}} - normalized (lowercased) keys
_ENTRIES: dict[str, dict] = {}
# Derived fast-lookup sets (exact IPs/full values + parent domains for suffix match)
_ATTACKER_EXACT: set[str] = set()
_ATTACKER_DOMAINS: set[str] = set()

# Lazy-sweep guard: sweep at most once per 60s to avoid O(n) on every is_attacker_ioc()
_LAST_SWEEP = 0.0
_SWEEP_INTERVAL = 60.0
# Guards the in-memory map and the JSONL rewrite. Cross-process writers still
# race (last replace wins); the atomic replace keeps the file parseable.
_LOCK = threading.RLock()

_SEP_CHARS = " /\\"

ANALYST_SOURCES = frozenset({"manual", "verdict", "analyst"})

# Sources that prove the value came out of Wazuh alert analysis. The automated
# VirusTotal workflow requires one of these: ``enrichment`` is registered by the
# lookup being authorized, and ``auto_promote`` counts repetition, so neither is
# evidence.
ALERT_SOURCES = frozenset({"engine_a", "verdict", "webshell_check", "wazuh_alerts"})
# The automated gate. An operator attestation is a different class: it is checked
# only by ``operator_ioc_evidence`` and only on the explicit CLI path.
TRUSTED_SOURCES = ALERT_SOURCES

# A trusted label alone is not proof. Each source must also carry the evidence
# its procedure produces; an entry without it is treated as unproven.
EVIDENCE_REQUIRED: dict[str, tuple[str, ...]] = {
    "wazuh_alerts": ("alert_id", "rule_id", "rule_level", "matched_field"),
    "engine_a": ("categories", "total"),
    "verdict": ("verdict",),
    "webshell_check": ("status",),
    "operator_cli": ("tool", "operator_attested"),
}


def _looks_like_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _looks_like_domain(v: str) -> bool:
    return "." in v and not any(c in v for c in _SEP_CHARS)


def _classify(v: str) -> str:
    """Return 'ip' | 'email' | 'domain' | 'other'."""
    if _looks_like_ip(v):
        return "ip"
    if "@" in v:
        return "email"
    if _looks_like_domain(v):
        return "domain"
    return "other"


def _add_entry(ioc: str, source: str, evidence: dict | None = None) -> None:
    """Insert a normalized entry into memory + derived sets."""
    _ENTRIES[ioc] = {"ts": time.time(), "source": source,
                     "evidence": dict(evidence or {})}
    kind = _classify(ioc)
    if kind == "domain":
        _ATTACKER_DOMAINS.add(ioc)
    elif kind == "email":
        dom = ioc.rsplit("@", 1)[-1]
        if _looks_like_domain(dom):
            _ATTACKER_DOMAINS.add(dom)
        _ATTACKER_EXACT.add(ioc)
    else:
        _ATTACKER_EXACT.add(ioc)


def _expired(entry: dict) -> bool:
    return _REGISTRY_TTL > 0 and (time.time() - entry["ts"]) > _REGISTRY_TTL


def _sweep_expired(force: bool = False) -> int:
    """Drop expired entries from memory; return count removed.
    Uses a 'lazy guard' - sweeps at most once per _SWEEP_INTERVAL seconds
    unless ``force=True`` (used by flush/clear paths).
    """
    global _LAST_SWEEP
    if not force:
        now = time.time()
        if now - _LAST_SWEEP < _SWEEP_INTERVAL:
            return 0
        _LAST_SWEEP = now
    else:
        _LAST_SWEEP = time.time()
    stale = [ioc for ioc, e in _ENTRIES.items() if _expired(e)]
    for ioc in stale:
        _remove_entry(ioc)
    return len(stale)


def _remove_entry(ioc: str) -> None:
    _ENTRIES.pop(ioc, None)
    _ATTACKER_EXACT.discard(ioc)
    _ATTACKER_DOMAINS.discard(ioc)


def _index(ioc: str) -> None:
    """Add one normalized key to the derived lookup sets."""
    kind = _classify(ioc)
    if kind == "domain":
        _ATTACKER_DOMAINS.add(ioc)
    elif kind == "email":
        dom = ioc.rsplit("@", 1)[-1]
        if _looks_like_domain(dom):
            _ATTACKER_DOMAINS.add(dom)
        _ATTACKER_EXACT.add(ioc)
    else:
        _ATTACKER_EXACT.add(ioc)


def _rebuild_index() -> None:
    _ATTACKER_EXACT.clear()
    _ATTACKER_DOMAINS.clear()
    for ioc in _ENTRIES:
        _index(ioc)


def _read_entries(path: Path) -> dict[str, dict]:
    """Parse one JSONL file. A corrupt line is skipped, never raised."""
    entries: dict[str, dict] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return entries
    now = time.time()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                continue
            ioc = (raw.get("ioc") or "").strip().lower()
            ts = float(raw.get("ts", 0))
            if not ioc:
                continue
            if _REGISTRY_TTL > 0 and (now - ts) > _REGISTRY_TTL:
                continue
            evidence = raw.get("evidence")
            entries[ioc] = {"ts": ts,
                            "source": str(raw.get("source", "persisted")),
                            "evidence": dict(evidence) if isinstance(evidence, dict) else {}}
        except (ValueError, TypeError):
            continue
    return entries


@contextlib.contextmanager
def _file_lock(exclusive: bool = True):
    """Advisory cross-process lock around one registry transaction.

    POSIX only. On a platform without ``fcntl`` this is a no-op, which is why
    the deployment target is Linux (see SECURITY.md §4.1g).
    """
    if not _REGISTRY_PATH or fcntl is None:
        yield
        return
    lock_path = Path(_REGISTRY_PATH + ".lock")
    created = not lock_path.parent.exists()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if created:
        os.chmod(lock_path.parent, 0o700)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _flush() -> None:
    """Merge this process's entries into the file under a cross-process lock.

    The read happens inside the lock, so a concurrent writer cannot be
    overwritten by a stale in-memory map. Replacement stays atomic for readers
    that do not take the lock.
    """
    if not _REGISTRY_PATH:
        return
    path = Path(_REGISTRY_PATH)
    with _LOCK, _file_lock():
        _sweep_expired(force=True)
        merged = _read_entries(path)
        for ioc, entry in _ENTRIES.items():
            current = merged.get(ioc)
            if current is None or entry["ts"] >= current["ts"]:
                merged[ioc] = entry
        _ENTRIES.clear()
        _ENTRIES.update(merged)
        _rebuild_index()
        if _REGISTRY_MAX > 0 and len(_ENTRIES) > _REGISTRY_MAX:
            for ioc in sorted(_ENTRIES, key=lambda k: _ENTRIES[k]["ts"])[:len(_ENTRIES) - _REGISTRY_MAX]:
                _remove_entry(ioc)
        try:
            created = not path.parent.exists()
            path.parent.mkdir(parents=True, exist_ok=True)
            if created:
                os.chmod(path.parent, 0o700)
            elif path.parent.stat().st_mode & 0o077:
                logger.warning("attacker registry directory %s is group/world "
                               "accessible; expected 0700", path.parent)
            tmp = path.with_suffix(".jsonl.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                for ioc, e in sorted(_ENTRIES.items()):
                    f.write(json.dumps({"ioc": ioc, "ts": round(e["ts"], 3),
                                        "source": e["source"],
                                        "evidence": e.get("evidence") or {}},
                                       ensure_ascii=False) + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except Exception:
            logger.warning("attacker registry flush failed", exc_info=True)


def _load() -> None:
    """Load persisted entries at import time."""
    if not _REGISTRY_PATH:
        return
    path = Path(_REGISTRY_PATH)
    if not path.exists():
        return
    try:
        with _file_lock(exclusive=False):
            entries = _read_entries(path)
    except OSError:
        logger.warning("attacker registry lock failed: %s", _REGISTRY_PATH)
        return
    _ENTRIES.update(entries)
    _rebuild_index()
    if entries:
        logger.info("attacker registry loaded %d entries from %s",
                    len(entries), _REGISTRY_PATH)


def register_attacker_ioc(value: str, source: str = "manual",
                          evidence: dict | None = None) -> None:
    """Register a single attacker indicator (IP, domain, or email).

    ``evidence`` records why the value is attributed to an attacker. A trusted
    source without evidence does not authorize a VirusTotal lookup.
    """
    v = (value or "").strip().lower()
    if not v:
        return
    with _LOCK:
        _add_entry(v, source, evidence)
        _flush()


def register_attacker_ips(values: list[str], source: str = "manual",
                          evidence: dict | None = None) -> None:
    for v in values or []:
        register_attacker_ioc(v, source=source, evidence=evidence)


def register_attacker_domains(values: list[str], source: str = "manual",
                              evidence: dict | None = None) -> None:
    for v in values or []:
        register_attacker_ioc(v, source=source, evidence=evidence)


def attacker_ioc_source(value: str) -> str | None:
    """Return the source that registered ``value``, or None when it is absent.
    Applies the same domain matching as ``is_attacker_ioc``: exact value, or
    exactly one subdomain level of a registered domain. Lazy-sweeps expired
    entries before checking.
    """
    _sweep_expired()  # lazy guard: O(1) unless interval elapsed
    v = (value or "").strip().lower()
    if not v:
        return None
    entry = _ENTRIES.get(v)
    if entry is not None:
        return str(entry.get("source") or "unknown")
    dom = v.rsplit("@", 1)[-1] if "@" in v else v
    # Match: exact domain OR exactly one subdomain level (e.g. www.evil.com)
    # matches evil.com, but subdo.evil.com does not).
    for d in _ATTACKER_DOMAINS:
        if dom == d or (dom.endswith("." + d) and "." not in dom[:-(len(d) + 1)]):
            entry = _ENTRIES.get(d)
            return str(entry.get("source") or "unknown") if entry else None
    return None


def reload_registry() -> None:
    """Re-read the JSONL file; tests and an operator re-sync use this."""
    with _LOCK:
        _ENTRIES.clear()
        _ATTACKER_EXACT.clear()
        _ATTACKER_DOMAINS.clear()
        _load()


def attacker_ioc_evidence(value: str) -> dict | None:
    """Return the stored attribution evidence, or ``None`` when unproven.

    A trusted source label is not enough: the entry must carry the keys its
    procedure produces and must record an ``accepted`` decision.
    """
    _sweep_expired()
    v = (value or "").strip().lower()
    if not v:
        return None
    entry = _ENTRIES.get(v)
    if entry is None:
        dom = v.rsplit("@", 1)[-1] if "@" in v else v
        for d in _ATTACKER_DOMAINS:
            if dom == d or (dom.endswith("." + d) and "." not in dom[:-(len(d) + 1)]):
                entry = _ENTRIES.get(d)
                break
    if entry is None or _expired(entry):
        return None
    source = str(entry.get("source") or "")
    evidence = entry.get("evidence") or {}
    if source not in TRUSTED_SOURCES or not isinstance(evidence, dict):
        return None
    if evidence.get("decision") != "accepted":
        return None
    if any(key not in evidence for key in EVIDENCE_REQUIRED.get(source, ())):
        return None
    return {"source": source, **evidence}


def operator_ioc_evidence(value: str) -> dict | None:
    """Return the operator attestation, or ``None``.

    Separate from ``attacker_ioc_evidence`` on purpose: a manually attested
    address is not Wazuh-verified, so the automated workflow never accepts it.
    """
    _sweep_expired()
    entry = _ENTRIES.get((value or "").strip().lower())
    if entry is None or _expired(entry):
        return None
    source = str(entry.get("source") or "")
    evidence = entry.get("evidence") or {}
    if source != "operator_cli" or not isinstance(evidence, dict):
        return None
    if evidence.get("decision") != "accepted" or evidence.get("operator_attested") is not True:
        return None
    if any(key not in evidence for key in EVIDENCE_REQUIRED["operator_cli"]):
        return None
    return {"source": source, **evidence}


def attacker_ioc_provenance(value: str) -> str | None:
    """Return the registering source when its evidence proves attribution.

    Same matching as ``attacker_ioc_source``. ``None`` means the value is
    unknown, expired, registered without evidence, or registered by a source
    that is not evidence, such as ``enrichment`` or ``auto_promote``.
    """
    evidence = attacker_ioc_evidence(value)
    return evidence["source"] if evidence else None


def is_attacker_ioc(value: str) -> bool:
    """True if value (or its domain) is a registered, unexpired attacker indicator."""
    return attacker_ioc_source(value) is not None


def registry_stats() -> dict:
    """Operational stats: size, TTL, cap, sources."""
    _sweep_expired(force=True)  # explicit diagnostic - always sweep
    sources: dict[str, int] = {}
    for e in _ENTRIES.values():
        sources[e["source"]] = sources.get(e["source"], 0) + 1
    def _mode(target: str | None) -> str | None:
        if not target:
            return None
        try:
            return oct(Path(target).stat().st_mode & 0o777)
        except OSError:
            return None

    return {
        "entries": len(_ENTRIES),
        "ttl_seconds": _REGISTRY_TTL,
        "max_entries": _REGISTRY_MAX,
        "persisted_path": _REGISTRY_PATH or None,
        "file_mode": _mode(_REGISTRY_PATH),
        "parent_mode": _mode(str(Path(_REGISTRY_PATH).parent)) if _REGISTRY_PATH else None,
        "lock_mode": _mode(_REGISTRY_PATH + ".lock") if _REGISTRY_PATH else None,
        "sources": sources,
    }


def clear_attacker_registry() -> None:
    """Clear all entries from memory (and the file if configured)."""
    with _LOCK, _file_lock():
        _ENTRIES.clear()
        _ATTACKER_EXACT.clear()
        _ATTACKER_DOMAINS.clear()
        if _REGISTRY_PATH:
            try:
                Path(_REGISTRY_PATH).unlink(missing_ok=True)
            except OSError:
                pass


_load()
