#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Paper evidence pack - hashed, k-anonymized snapshot for manuscript drafting.

Writes only inside BLUETEAM_EXPORT_DIR. No egress, no subprocess beyond a local
`git rev-parse`/`git status`, no compilation. The pack is the input to
`blueteam_export_report(format="latex")` and the reference set for
`blueteam_paper_claim_check`; PaperOrchestra reads it outside the server.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_server import mcp
from mcp_server.core import case_store, metrics, paper_evidence
from mcp_server.core.paper_alerts import alert_summary
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.config import config
from mcp_server.core.subprocess import _validate_path

REPO_ROOT = Path(__file__).resolve().parents[2]


class ClaimCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    draft: str = Field(..., min_length=1, max_length=50000)
    claims_path: str = Field(..., max_length=500,
        description="Absolute path to an evidence pack claims.json.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


class EvaluationRecord(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., min_length=1, max_length=120)
    command: str = Field(default="", max_length=300)
    passed: int = Field(..., ge=0)
    total: int = Field(..., ge=0)
    duration_s: float = Field(default=0.0, ge=0)

    @model_validator(mode="after")
    def _passed_within_total(self):
        if self.passed > self.total:
            raise ValueError("passed cannot exceed total")
        return self


class PaperEvidenceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    output_dir: Optional[str] = Field(default=None, max_length=500,
        description="Absolute pack directory. Defaults to <BLUETEAM_EXPORT_DIR>/paper/<run_id>.")
    run_id: Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,47}$",
        description="Pack identifier, lowercase letters/digits/hyphens.")
    evaluations: list[EvaluationRecord] = Field(default_factory=list, max_length=50,
        description="CI or benchmark results to include; omitted means none were supplied.")
    alert_window_minutes: int = Field(default=1440, ge=1, le=43200,
        description="Lookback window in minutes for the alert summary in alerts.json.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(
    name="blueteam_paper_evidence_pack",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_paper_evidence_pack(params: PaperEvidenceInput) -> str:
    """Write a hashed evidence pack for manuscript drafting.

    Contains the registered tool inventory, telemetry snapshot, case summaries,
    indexer alert summary for the requested window, supplied evaluation
    results, plot-ready CSVs, and claim IDs. Case titles,
    notes, IOCs, srcips, and alert payloads are never written; a per-entity cell
    backed by fewer than 5 distinct source IPs is suppressed.

    Only claims with ``citable: true`` may appear in a manuscript. Degenerate
    values stay in the pack as proof the pipeline ran, marked non-citable with
    the reason (empty case store, no recorded calls).

    **Worked Examples**
    1. ``blueteam_paper_evidence_pack(run_id="draft-01")``
    2. ``blueteam_paper_evidence_pack(run_id="draft-02", evaluations=[{"name": "pytest", "passed": 412, "total": 412}])``
    """
    run_id = params.run_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    export_root = config.operational.export_dir
    target = os.path.abspath(params.output_dir or os.path.join(export_root, "paper", run_id))

    ok, err = _validate_path(target, [export_root])
    if not ok:
        return json.dumps({"error": f"Path not allowed: {err}", "allowed": [export_root]},
                          indent=2)
    # Snapshot before the audit so the pack does not count its own invocation.
    snapshot = metrics.snapshot()
    alerts = await alert_summary(params.alert_window_minutes)
    _audit_log("blueteam_paper_evidence_pack",
               {"run_id": run_id, "output_dir": target, "evaluations": len(params.evaluations)})

    tools = {tool.name: tool for tool in mcp._tool_manager.list_tools()}
    try:
        manifest = await asyncio.to_thread(
            paper_evidence.build_evidence_pack,
            target, run_id,
            tools=tools,
            metrics_snapshot=snapshot,
            cases=case_store.list_cases(),
            evaluations=[e.model_dump() for e in params.evaluations],
            repo_root=REPO_ROOT,
            alerts=alerts,
            gating={
                "read_only": config.tool_gating.read_only,
                "disabled_categories": sorted(config.tool_gating.disabled_categories),
                "disabled_tools": sorted(config.tool_gating.disabled_tools),
            },
        )
    except OSError as exc:
        return json.dumps({"error": f"Evidence pack write failed: {exc}"}, indent=2)

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(manifest, indent=2, ensure_ascii=False))

    files = "\n".join(f"- `{f['path']}` ({f['bytes']} B)" for f in manifest["files"])
    git = manifest["git"]
    summary = (
        f"# Evidence pack `{manifest['pack_id']}`\n\n"
        f"- Path: `{target}`\n"
        f"- Commit: `{git['commit']}` (dirty: `{git['dirty']}`)\n"
        f"- Tools: {len(tools)}\n"
        f"- Alerts: " + (f"{alerts['total']} in {alerts['window_minutes']} min\n"
                         if alerts.get("available") else
                         f"unavailable ({alerts.get('error_kind', 'not_collected')})\n") +
        f"- Files: {len(manifest['files'])}\n"
        f"- Claims: {manifest['claims']['citable']} of {manifest['claims']['total']} citable\n"
        f"- Content hash: `{manifest['content_hash']}`\n"
        f"- k-anonymity: {manifest['k_anonymity']} | min evidence n: {manifest['min_evidence_n']}\n\n"
        f"## Files\n{files}\n\n"
        "No raw IPs, case text, or alert payloads are written. Only claims with "
        "`citable: true` in `claims.json` may be cited; the rest prove the pipeline ran."
    )
    return _truncate_if_needed(summary)


@mcp.tool(
    name="blueteam_paper_claim_check",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_paper_claim_check(params: ClaimCheckInput) -> str:
    """Validate a manuscript draft against an evidence pack.

    Resolves ``{{C-001}}`` tokens and every bare number against claims with
    ``citable: true``. An unknown or non-citable claim fails with its recorded
    reason. A number no citable claim supports is reported with its context.
    Structural references and CVE, CWE, ATT&CK, and rule IDs are ignored.

    **Worked Examples**
    1. ``blueteam_paper_claim_check(draft="The server exposes {{C-001}} tools.", claims_path="/var/log/blue-team-mcp/exports/paper/draft-01/claims.json")``
    2. ``blueteam_paper_claim_check(draft="Only 3 cases were seen.", claims_path=".../claims.json")``
    3. ``blueteam_paper_claim_check(draft="...", claims_path=".../claims.json", response_format="json")``
    """
    export_dir = config.operational.export_dir
    claims_abs = os.path.abspath(params.claims_path)
    ok, err = _validate_path(claims_abs, [export_dir])
    if not ok:
        return json.dumps({"error": f"claims_path not allowed: {err}",
                           "allowed": [export_dir]}, indent=2)

    claims, err = paper_evidence.load_claims(claims_abs)
    if err:
        return json.dumps({"error": err}, indent=2)
    manifest = paper_evidence.load_manifest(Path(claims_abs).parent / "manifest.json")
    result = paper_evidence.check_draft(
        params.draft, claims, str(manifest.get("pack_status") or "unknown"))
    _audit_log("blueteam_paper_claim_check",
               {"claims_path": claims_abs, "ok": result["ok"],
                "unsupported": len(result["unsupported_numbers"]),
                "errors": len(result["errors"])})

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    verdict = "PASS" if result["ok"] else "FAIL"
    lines = [f"# Claim check — {verdict}", "",
             f"- Pack status: `{result['pack_status']}`",
             f"- Claims resolved: {result['claims_resolved']}",
             f"- Unsupported numbers: {len(result['unsupported_numbers'])}",
             f"- Claim errors: {len(result['errors'])}"]
    if result["errors"]:
        lines += ["", "## Claim errors"]
        lines += [f"- `{e['claim_id']}` — {e['reason']}" for e in result["errors"]]
    if result["unsupported_numbers"]:
        lines += ["", "## Unsupported numbers"]
        lines += [f"- `{u['number']}` — ...{u['context']}..." for u in result["unsupported_numbers"]]
    return _truncate_if_needed("\n".join(lines))
