#!/usr/bin/env python3
"""Structural readiness gate for the label / classify / cluster rollout; no model
load, no network. --strict exits 1 on FAIL, --expect-artifacts requires the Phase 3
caches, and WAZUH_INDEXER_URL/PASSWORD are needed for the tool-schema section.
"""
from __future__ import annotations
import argparse, asyncio, importlib.util, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

OK, FAIL, NOTE = "OK", "FAIL", "NOTE"
results: list[tuple[str, str]] = []

def report(status: str, name: str, detail: str = "") -> None:
    results.append((status, name))
    print(f"[{status:4}] {name}" + (f" - {detail}" if detail else ""))


def check_imports() -> None:
    for module, needed in (("sklearn", "cluster phase"), ("fastembed", "ONNX label + rerank"),
                           ("onnxruntime", "ONNX runtime"), ("torch", "laya backend only")):
        found = importlib.util.find_spec(module) is not None
        report(OK if found else (FAIL if module == "sklearn" else NOTE),
               f"import: {module}", "present" if found else f"missing ({needed})")


def check_artifacts(expect: bool) -> None:
    for name, env, default in (("RAG embedder cache", "BLUETEAM_RAG_CACHE_PATH", "rag-cache"),
                               ("Rerank cache", "BLUETEAM_RERANK_CACHE_PATH", "rerank-cache")):
        path = Path(os.environ.get(env) or Path.cwd() / default)
        files = sum(1 for _ in path.rglob("*")) if path.is_dir() else 0
        report(OK if files else (FAIL if expect else NOTE), f"artifacts: {name}",
               f"{path} ({files} files)" if files else f"absent at {path}")


def check_stores() -> None:
    clusters = os.environ.get("BLUETEAM_CLUSTER_STORE", "")
    parent = Path(clusters).parent if clusters else None
    if parent is None:
        report(NOTE, "store: cluster db", "BLUETEAM_CLUSTER_STORE unset")
    elif parent.is_dir() and os.access(parent, os.W_OK):
        report(OK, "store: cluster db parent", f"{parent} writable")
    else:
        report(NOTE, "store: cluster db parent", f"{parent} missing or read-only")


def _fields(schema: dict) -> set[str]:
    """Tool input models are nested under properties.params as a $ref."""
    node = (schema.get("properties") or {}).get("params") or {}
    ref = node.get("$ref", "")
    if ref.startswith("#/$defs/"):
        node = (schema.get("$defs") or {}).get(ref.rsplit("/", 1)[-1]) or {}
    return set((node.get("properties") or {}).keys())


def check_tools() -> None:
    try:
        from mcp_server import mcp
        from mcp_server.tools import register_all_tools
        register_all_tools()
        tools = {t.name: (getattr(t, "inputSchema", None) or {})
                 for t in asyncio.run(mcp.list_tools())}
    except Exception as exc:
        report(NOTE, "tool schemas", f"skipped: {exc}")
        return
    expected = {"blueteam_incident_label": ("mode", "text", "alert"),
                "blueteam_alert_cluster": ("mode", "time_window_minutes"),
                "blueteam_alert_cluster_assign": ("srcip", "time_window_minutes"),
                "blueteam_attack_graph": ("window_days", "top_n"),
                "blueteam_campaign_watch": ("window_days", "top_n")}
    for tool, fields in expected.items():
        props = _fields(tools.get(tool) or {})
        missing = [field for field in fields if field not in props]
        report(FAIL if missing else OK, f"schema: {tool}",
               f"missing {missing}" if missing else f"{len(props)} fields")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="exit 1 on any FAIL")
    parser.add_argument("--expect-artifacts", action="store_true",
                        help="model caches must be present (Phase 3 stage run)")
    args = parser.parse_args()
    print("== structural readiness (no model load, no network) ==")
    check_imports()
    check_artifacts(args.expect_artifacts)
    check_stores()
    check_tools()
    failed = [name for status, name in results if status == FAIL]
    print(f"== {len(results) - len(failed)}/{len(results)} checks clean ==")
    if failed and args.strict:
        print("FAIL: " + "; ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
