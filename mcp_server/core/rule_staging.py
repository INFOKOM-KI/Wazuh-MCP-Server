#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Shared rule staging helpers.

Both synthesizers write human reviewed drafts to a STAGING directory:
  * ``tools/yara_rules.py``   -> ``<family>_<plat>_Wazuh_<MonYY>_<digest>.yar``
  * ``tools/sigma_rules.py``  -> ``sigma_<...>_<digest>.yml``

This module is the single write boundary, so the traversal guard is audited
once instead of once per synthesizer. A second, drifting copy of that guard is
the failure that matters here.

Nothing written here is ever loaded by a live engine. Promotion to a production
``rules.d`` / ``etc/rules`` path is a manual SOC Engineer step.

NOTE: No ``from __future__ import annotations`` it breaks @blueteam_tool type resolution in calling modules (PEP 563).
"""

import hashlib
import os
import re
from pathlib import Path
from mcp_server.core.exceptions import BlueTeamMCPError

# Filename stem: starts alphanumeric, then [A-Za-z0-9_.-]. The suffix is a
# separate, caller-supplied literal (.yar/.yml) so a YARA draft can never be
# saved under a Sigma extension, or vice versa.
_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,118}$")


def staging_dir(group: str, fallback: str) -> Path:
    """Staging directory for a config group ("yara" / "sigma").
    Reads ``config.<group>.rules_dir``; falls back to ``fallback`` when the
    config singleton is unavailable (unit tests, bare imports).

    Args:
        group: attribute name on the Config singleton, e.g. "yara".
        fallback: absolute path used when config is missing.

    Returns:
        Path to the staging directory. Not created here.
    """
    from mcp_server.core.config import config as _cfg

    group_cfg = getattr(_cfg, group, None) if _cfg is not None else None
    return Path(getattr(group_cfg, "rules_dir", "") or fallback)


def short_digest(*parts: bytes | str, length: int = 12) -> str:
    """Stable short hex digest over ordered, de-duplicated parts.
    Order insensitive for the same set of parts, so a digest embedded in a rule
    name does not change when the caller's iteration order does.

    Args:
        *parts: bytes or str pieces (str is utf-8 encoded, errors ignored).
        length: hex characters to keep.

    Returns:
        Lowercase hex prefix of the sha256 over the parts joined by NUL.
    """
    ordered = sorted({p.encode("utf-8", "ignore") if isinstance(p, str) else p
                      for p in parts})
    return hashlib.sha256(b"\x00".join(ordered)).hexdigest()[:length]


def safe_filename(filename: str, suffix: str) -> bool:
    """True when ``filename`` is a bare ``<stem><suffix>`` with no traversal."""
    if not filename or not suffix or not filename.endswith(suffix):
        return False
    if ".." in filename:
        return False
    stem = filename[: -len(suffix)]
    return bool(_STEM_RE.match(stem))


def save_rule_file(rule_source: str, filename: str, overwrite: bool,
                   rules_dir: Path, suffix: str) -> Path:
    """Write ``rule_source`` into ``rules_dir`` atomically at ``filename``.
    The only write boundary for synthesised rules. Refuses any filename that is
    not a bare ``<stem><suffix>``, and any path that resolves outside
    ``rules_dir`` (traversal, symlink escape, absolute path).

    Args:
        rule_source: Full rule text, already validated by the caller.
        filename: Target filename, e.g. "MAL_X_Win_Jan25_ab12cd34ef56.yar".
        overwrite: Replace an existing file. False refuses.
        rules_dir: Staging directory (created if absent).
        suffix: Required extension literal, e.g. ".yar" or ".yml".

    Returns:
        Path to the written file.

    Raises:
        BlueTeamMCPError: bad filename, traversal, or existing file without
            ``overwrite``.
    """
    if not safe_filename(filename, suffix):
        raise BlueTeamMCPError(
            f"Invalid rule filename {filename!r}: use [A-Za-z0-9_.-] and a {suffix!r} suffix"
        )
    rules_dir.mkdir(parents=True, exist_ok=True)
    root = rules_dir.resolve()
    target = (root / filename).resolve()
    try:
        target.relative_to(root)
    except ValueError as e:
        raise BlueTeamMCPError(f"Refusing to write outside {root}: {target}") from e
    if target.exists() and not overwrite:
        raise BlueTeamMCPError(
            f"{target.name} already exists in the staging dir; pass overwrite=true to replace"
        )
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(rule_source, encoding="utf-8")
    os.replace(tmp, target)
    return target


if __name__ == "__main__":
    # Self-check: suffix enforcement and the traversal guard are the security
    # surface here, so they get the runnable check.
    import tempfile

    assert safe_filename("MAL_X_Win_Jan25_ab12cd34ef56.yar", ".yar")
    assert not safe_filename("MAL_X_Win_Jan25_ab12cd34ef56.yar", ".yml"), "suffix must be enforced"
    assert not safe_filename("../../etc/cron.d/x.yar", ".yar"), "traversal must be rejected"
    assert not safe_filename("/etc/passwd.yar", ".yar"), "absolute must be rejected"
    assert not safe_filename(".yar", ".yar"), "empty stem must be rejected"
    assert not safe_filename("a..b.yar", ".yar"), "embedded .. must be rejected"
    assert not safe_filename("x.yml", ".yar"), "wrong extension must be rejected"

    # Digest is order-insensitive and stable.
    assert short_digest(b"one", b"two") == short_digest("two", "one")
    assert len(short_digest("x")) == 12

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        p = save_rule_file("rule t { condition: true }", "t_rule.yar", False, root, ".yar")
        assert p.read_text() == "rule t { condition: true }"
        try:
            save_rule_file("dup", "t_rule.yar", False, root, ".yar")
            raise AssertionError("duplicate save must be refused")
        except BlueTeamMCPError:
            pass
        assert save_rule_file("dup", "t_rule.yar", True, root, ".yar").exists()
        assert not list(root.glob("*.tmp")), "no temp file may survive"
    print("rule_staging self-check OK")
