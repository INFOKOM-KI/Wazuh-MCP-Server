# Blue Team MCP Server (Wazuh SIEM)

A defensive MCP server for Claude Desktop / any MCP client — the blue-team counterpart to
offensive tooling. Exposes **90+ SOC tools** across Wazuh SIEM, multi-provider threat
intelligence, alert enrichment, MITRE-driven 3-Sum APT correlation, attack graphing, LangGraph
investigation workflows, and host forensics. Read-only by default.

**Programmer**: `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)

---

## Architecture

```
main.py  ──►  mcp_server/  (package)
                 ├─ core/          HTTP client, redaction, audit, config, attack graph, IOC store
                 ├─ wazuh/         Indexer (OpenSearch) + Manager API (JWT auth)
                 ├─ correlation/   3-Sum engine (pure computation, MITRE-driven)
                 ├─ threat_intel/  CrowdSec, ThreatFox, OTX, URLhaus, GreyNoise + shared cache
                 ├─ agents/        LangGraph investigation + playbook workflows
                 └─ tools/         44 tool modules
```

| Transport | Use case |
|-----------|----------|
| `stdio` | Local subprocess / SSH pipe (default) |
| `streamable_http` | Remote HTTP service (`http://<host>:<port>/mcp`) — requires auth beyond `127.0.0.1` |

---

## Quick Start

```bash
git clone <repo> && cd Wazuh-MCP-Server
sudo bash setup.sh                    # deps, venv, wrapper at /opt/blue-team-mcp

# configure (edit /opt/blue-team-mcp/config.env)
export WAZUH_INDEXER_URL="https://<host>:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="<indexer-password>"
export WAZUH_API_URL="https://<host>:55000"      # optional — Manager API tools
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="<api-password>"
export CROWDSEC_API_KEY="<key>"                  # optional — threat intel (free)
export BLUETEAM_CMDB_FILE="/var/log/blue-team-mcp/cmdb_inventory.json"

# run (stdio)
mcp-server-blueteam

# or remote HTTP
MCP_TRANSPORT=streamable_http MCP_HOST=0.0.0.0 MCP_PORT=8001 mcp-server-blueteam
```

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "command": "ssh",
      "args": ["-i", "~/.ssh/id_ed25519", "user@DEFENDER_HOST", "mcp-server-blueteam"],
      "transport": "stdio"
    }
  }
}
```

---

## Configuration

Credentials come from environment variables, validated at startup. Every threat-intel key is
optional — tools degrade gracefully without them.

| Area | Variables | Notes |
|------|-----------|-------|
| Wazuh Indexer | `WAZUH_INDEXER_URL` / `_USER` / `_PASSWORD` | OpenSearch (9200) — alert/event data |
| Wazuh Manager | `WAZUH_API_URL` / `_USER` / `_PASSWORD` | Manager API (55000) — rules/agents/config |
| TLS | `WAZUH_INDEXER_VERIFY_SSL`, `WAZUH_API_VERIFY_SSL` | default `true` |
| Threat intel | `CROWDSEC_API_KEY`, `THREATFOX_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `NETRA_API_KEY`, `ARGUS_API_KEY`, `GREYNOISE_BASE_URL` | 9 providers; all optional |
| Redaction | `BLUETEAM_REDACTION_POLICY`, `BLUETEAM_OWNED_DOMAINS`, `BLUETEAM_REDACT_*` | see Security & Privacy |
| Forensic gate | `BLUETEAM_ALLOW_FORENSIC_BYPASS`, `BLUETEAM_FORENSIC_TOKEN` | default `false` / empty |
| Audit | `BLUETEAM_AUDIT_LOG` | JSONL audit trail (optional) |
| Persistence | `BLUETEAM_IOC_STORE`, `BLUETEAM_ATTACKER_REGISTRY`, `BLUETEAM_CAMPAIGN_SNAPSHOTS`, `BLUETEAM_EXPORT_DIR`, `BLUETEAM_CMDB_FILE` | JSONL stores + export dir |
| Gating | `WAZUH_READ_ONLY`, `WAZUH_DISABLED_CATEGORIES` | skip destructive tools / tool categories |

---

## Capabilities

### Wazuh SIEM
Alert search (`blueteam_wazuh_indexer_search`, `wazuh_alert_dsl_query`), zero-doc statistical
aggregations, schema discovery (`blueteam_index_schema`), domain/email/geo/syscheck/compliance
lookups, and Manager API tools (rules, decoders, groups, agents, security events).

### 3-Sum APT Correlation
`three_sum_correlation` runs two engines plus unified scoring:
- **Engine A** — MITRE-driven multi-IoC risk thresholding. Alerts classify by
  `rule.mitre.tactic` (via `MITRE_TACTIC_TO_CATEGORY`) and `rule.mitre.id` (resolved through the
  ATT&CK STIX bundle), scored dynamically as `rule.level × tactic weight`, and gated by a
  **≥2-category chained-attack rule** (`threshold_score` default 35).
- **Engine B** — 3-source volumetric Z-score (MAD + shoulder-check) flagging simultaneous spikes.
- Plus multi-resolution (1h/24h/7d) and Indexer degradation detection.

### Threat Intelligence
9 providers — CrowdSec, ThreatFox, OTX, URLhaus, GreyNoise, AbuseIPDB, VirusTotal, Netra, Argus —
with a unified `blueteam_threat_intel_aggregate` (fans out to six sources concurrently) and a
weighted `blueteam_unified_threat_score`.

### Alert Enrichment
`blueteam_wazuh_alert_summarize`, `blueteam_beacon_detect`, `blueteam_attack_chain`,
`blueteam_threat_card`, `blueteam_wazuh_alert_compare`, `blueteam_curated_threat_report`.

### Investigation, Graphs & Workflows
`blueteam_investigate_ip`, `blueteam_attack_graph` (networkx clusters + PageRank suspicion),
`blueteam_campaign_watch`, `blueteam_stix_killchain`, `blueteam_investigation_workflow` and
`blueteam_playbook_run` (LangGraph), plus investigation history and false-positive tracking.

### Host & Domain Forensics
WHOIS / CRT.sh, IOC extraction, webshell scanning, server-side JSONL export,
DOCX/XLSX/PPTX report export, and 23 host-forensics tools (log readers, fail2ban, rootkit scan,
lynis, process/cron/users).

---

## Security & Privacy

Three-state redaction policy (`BLUETEAM_REDACTION_POLICY`, default **`full`**):

| Policy | Behavior |
|--------|----------|
| `full` | Shape-based masking of emails, private IPs, all domains, paths, user-agents |
| `protect_victim` | Mask only victim-owned indicators (owned domains, private IPs, identities); attacker IOCs stay visible. Recommended for SOC triage. |
| `raw` | Layer-1 credential strip only — hard-gated behind `BLUETEAM_ALLOW_FORENSIC_BYPASS=true` + `BLUETEAM_FORENSIC_TOKEN` |

Layer 1 (credential stripping) applies in **all** states and is never bypassable. Attacker-IOC
registry (`core/attacker_registry.py`) exempts confirmed attacker indicators from shape-based
masking.

Two-tier unmasking on top of the policy:
- **Tier 1 — `reveal_owned=true`** — reveals only owned `*.tangerangkota.go.id` assets to the LLM.
- **Tier 2 — `bypass_redaction=true` + `forensic_token`** — writes raw data **to disk**; the LLM
  receives only the file path, never the raw content.

---

## Requirements

- Python 3.11+
- `mcp`, `httpx[http2]`, `pydantic`, `networkx`, `langgraph`, `officecli-sdk`
- See `requirements.txt`.

---

## Development Guardrails

- `python3 check_guardrails.py --strict` must pass (exit 0) before merge.
- Every tool sets `readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint` explicitly.
- Logging → stderr only (stdout is the JSON-RPC channel).
- Pure-computation modules (`three_sum_core.py`) stay stdlib + pure `core.constants` only.
- Operational runbooks and tool-usage guides live in `PROMPT.md` / `SKILLS.md`, not here.
