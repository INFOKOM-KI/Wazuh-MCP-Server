#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
STIX 2.1 object factory for outbound ("egress") objects.

Producer-side counterpart to ``mcp_server/tools/stix_correlation.py``, which only
*consumes* the MITRE ATT&CK STIX bundle. No ``stix2`` dependency here either:
objects are plain dicts conforming to STIX 2.1 CS02, so a receiving platform can
parse the bundle with any conformant consumer (verified against stix2 3.0.1 -
see tests/test_stix_export.py).

Deterministic IDs: SDO ids are UUIDv5 in the namespace from
``BLUETEAM_STIX_NAMESPACE`` (default ``uuid5(NAMESPACE_DNS, "tangerangkota.go.id")``),
derived from the object's semantic key - for an indicator, the *pattern*, not its
description or source list. Re-exporting the same indicator therefore produces the
same id across exports, so a peer deduplicates instead of accumulating copies.
Bundle ids are UUIDv4: a bundle is an export event, not a content-addressable object.

Spec-mandated instances (do not "improve" them): the four TLP marking-definitions
below carry the fixed id/created/name/definition of the STIX 2.1 specification.
A conformant consumer rejects a TLP marking-definition whose instance differs, so
editing a field here breaks interop instead of extending it. Additional markings
(TLP 2.0 ``TLP:CLEAR`` / ``TLP:AMBER+STRICT``, or an org statement marking) are
loaded from ``BLUETEAM_STIX_MARKINGS_FILE`` - see ``load_markings_file()``.

Configuration (read at call time, no startup validation - the exporter is opt-in):
  BLUETEAM_STIX_EGRESS_ENABLED  "true" to allow any bundle to be produced (default false)
  BLUETEAM_STIX_IDENTITY_NAME   producer organization name (required to export)
  BLUETEAM_STIX_IDENTITY_SECTORS     comma-separated STIX sectors (default "government")
  BLUETEAM_STIX_IDENTITY_CONTACT     contact_information string (default empty)
  BLUETEAM_STIX_NAMESPACE       UUID to use as the UUIDv5 namespace (default above)
  BLUETEAM_STIX_DEFAULT_TLP     WHITE | GREEN | AMBER | RED (default AMBER)
  BLUETEAM_STIX_MARKINGS_FILE   JSON file with extra marking-definition objects
"""
from __future__ import annotations
import json
import logging
import os
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("blue_team_mcp.stix_objects")

STIX_SPEC_VERSION = "2.1"

_NAMESPACE_DEFAULT = str(uuid.uuid5(uuid.NAMESPACE_DNS, "tangerangkota.go.id"))
_MARKINGS_FILE_MAX_BYTES = 1024 * 1024

TLP_LEVELS = ("WHITE", "GREEN", "AMBER", "RED")

TLP_MARKING_DEFINITIONS: dict[str, dict] = {
    "WHITE": {
        "type": "marking-definition", "spec_version": STIX_SPEC_VERSION,
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    },
    "GREEN": {
        "type": "marking-definition", "spec_version": STIX_SPEC_VERSION,
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "AMBER": {
        "type": "marking-definition", "spec_version": STIX_SPEC_VERSION,
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "RED": {
        "type": "marking-definition", "spec_version": STIX_SPEC_VERSION,
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}


def utcnow_z() -> str:
    """Current UTC time as a STIX timestamp (millisecond precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def stix_id(obj_type: str, semantic_key: str) -> str:
    """Deterministic STIX id: ``<type>--<uuid5(namespace, "<type>:<key>")>``."""
    ns = _namespace()
    return f"{obj_type}--{uuid.uuid5(ns, f'{obj_type}:{semantic_key}')}"


def new_bundle_id() -> str:
    """Fresh bundle id (UUIDv4 - a bundle is an export event, not an object)."""
    return f"bundle--{uuid.uuid4()}"


def _namespace() -> uuid.UUID:
    """UUIDv5 namespace from BLUETEAM_STIX_NAMESPACE, falling back to the default.
    A malformed value falls back instead of raising: the failure mode of a bad
    namespace is duplicate ids at the peer, which is visible and recoverable,
    while a raised error here would take the exporter offline entirely.
    """
    raw = os.environ.get("BLUETEAM_STIX_NAMESPACE", "").strip()
    if not raw:
        return uuid.UUID(_NAMESPACE_DEFAULT)
    try:
        return uuid.UUID(raw)
    except ValueError:
        logger.warning("BLUETEAM_STIX_NAMESPACE=%r is not a UUID using the default namespace", raw)
        return uuid.UUID(_NAMESPACE_DEFAULT)


def egress_enabled() -> bool:
    """True when BLUETEAM_STIX_EGRESS_ENABLED is truthy. Default: disabled."""
    return os.environ.get("BLUETEAM_STIX_EGRESS_ENABLED", "false").strip().lower() in (
        "1", "true", "yes", "on")


def default_tlp() -> str:
    """Default TLP level for a bundle: BLUETEAM_STIX_DEFAULT_TLP (fallback AMBER)."""
    raw = os.environ.get("BLUETEAM_STIX_DEFAULT_TLP", "AMBER").strip().upper()
    if raw not in TLP_LEVELS:
        logger.warning("BLUETEAM_STIX_DEFAULT_TLP=%r is not a TLP level - using AMBER", raw)
        return "AMBER"
    return raw


def tlp_marking_definition(level: str) -> dict:
    """The spec-mandated marking-definition object for a TLP level (copy)."""
    return dict(TLP_MARKING_DEFINITIONS[level.upper()])


def tlp_ref(level: str) -> str:
    """The marking-definition id to place in ``object_marking_refs``."""
    return TLP_MARKING_DEFINITIONS[level.upper()]["id"]


def identity_from_env() -> dict | None:
    """Producer Identity object built from env, or None when unnamed.
    ``identity_class`` is "organization" and the id derives from the name, so the
    same deployment always advertises the same producer identity to peers.
    """
    name = os.environ.get("BLUETEAM_STIX_IDENTITY_NAME", "").strip()
    if not name:
        return None
    sectors = [s.strip().lower() for s in
               os.environ.get("BLUETEAM_STIX_IDENTITY_SECTORS", "government").split(",")
               if s.strip()]
    obj = {
        "type": "identity", "spec_version": STIX_SPEC_VERSION,
        "id": stix_id("identity", name),
        "created": utcnow_z(), "modified": utcnow_z(),
        "name": name, "identity_class": "organization",
    }
    if sectors:
        obj["sectors"] = sectors
    contact = os.environ.get("BLUETEAM_STIX_IDENTITY_CONTACT", "").strip()
    if contact:
        obj["contact_information"] = contact
    return obj


def identity_config_error() -> str | None:
    """Error text when the producer identity is unconfigured, else None."""
    if os.environ.get("BLUETEAM_STIX_IDENTITY_NAME", "").strip():
        return None
    return ("BLUETEAM_STIX_IDENTITY_NAME is not set. A shared bundle needs a producer "
            "Identity (who produced this intelligence), e.g. "
            "BLUETEAM_STIX_IDENTITY_NAME='TangerangKota CSIRT'.")


def load_markings_file(path: str | None = None) -> tuple[list[dict], str]:
    """Load extra marking-definition objects from BLUETEAM_STIX_MARKINGS_FILE.
    Accepts a JSON list, a STIX bundle, or a single object. Use for markings this
    module does not ship: TLP 2.0 (``TLP:CLEAR``, ``TLP:AMBER+STRICT``) or a
    statement marking carrying the org's sharing rules.

    Returns (objects, error). Missing configuration yields ([], ""). Each object is
    validated for type/id/name/definition before it can reach a bundle.
    """
    src = path if path is not None else os.environ.get("BLUETEAM_STIX_MARKINGS_FILE", "")
    src = (src or "").strip()
    if not src:
        return [], ""
    try:
        if os.path.getsize(src) > _MARKINGS_FILE_MAX_BYTES:
            return [], f"markings file exceeds {_MARKINGS_FILE_MAX_BYTES} bytes"
        with open(src, encoding="utf-8") as f:
            raw = json.load(f)
    except OSError as e:
        return [], f"markings file unreadable: {e}"
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return [], f"markings file is not valid JSON: {e}"

    if isinstance(raw, dict):
        raw = raw.get("objects", [raw])
    if not isinstance(raw, list):
        return [], "markings file must contain a marking-definition, a list, or a bundle"

    out: list[dict] = []
    for obj in raw:
        if not isinstance(obj, dict):
            return [], "markings file contains a non-object entry"
        if obj.get("type") != "marking-definition":
            return [], f"markings file entry has type={obj.get('type')!r}, expected 'marking-definition'"
        if not str(obj.get("id", "")).startswith("marking-definition--"):
            return [], "markings file entry has a malformed id"
        if not obj.get("name") or "definition" not in obj:
            return [], "markings file entry is missing name/definition"
        out.append(obj)
    return out, ""
