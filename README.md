# Blue Team MCP Server (Wazuh SIEM)

A defensive MCP server for Claude Desktop / any MCP client — the blue-team counterpart to
offensive tooling. Exposes **100+ SOC tools** across Wazuh SIEM, multi-provider threat
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
| Threat intel | `CROWDSEC_API_KEY`, `THREATFOX_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `NETRA_API_KEY`, `ARGUS_API_KEY`, `GREYNOISE_BASE_URL`, `RAPIDAPI_KEY` | 9 providers + 3 RapidAPI lookups; all optional |
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
weighted `blueteam_unified_threat_score`. Plus 3 RapidAPI capability lookups:
`blueteam_ip_blacklist` (blacklist verdict), `blueteam_ioc_search` (IOC/malware matches), and
`blueteam_breach_check` (email breach status) — all keyed by `RAPIDAPI_KEY`.

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

## SOC Analysis Prompt (copy-paste for your LLM)

A ready-to-paste prompt for a **local** LLM connected to this MCP server. Two output formats —
**Markdown** (inline report, no extra deps) and **DOCX** (OfficeCLI report).

> **DOCX requires OfficeCLI** — install it first (see below). The Markdown path needs nothing extra.

**OfficeCLI install**:

```bash
# macOS / Linux — or: brew install officecli / npm install -g @officecli/officecli
curl -fsSL https://raw.githubusercontent.com/iOfficeAI/OfficeCLI/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/iOfficeAI/OfficeCLI/main/install.ps1 | iex
```

```
⚠️ EXECUTION RULES (parameter guardrails — prevents false positives):
- redaction_policy="protect_victim" is accepted by ONLY 5 tools:
    blueteam_curated_threat_report, blueteam_wazuh_alert_summarize,
    blueteam_wazuh_indexer_search, three_sum_correlation, blueteam_investigate_ip
- blueteam_wazuh_export uses bypass_redaction (NOT redaction_policy) — forensic export to disk only.
- Other tools DO NOT accept redaction_policy. If a call returns "extra_forbidden", drop the param and retry.
- blueteam_export_report does NOT support reveal_owned; it supports ONLY docx/xlsx/pptx.
- Export path MUST be /var/log/blue-team-mcp/exports/.

⚠️ TWO-TIER UNMASKING:
- TIER 1 — reveal_owned=true (SAFE for LLM, own assets only): reveals only
  *.tangerangkota.go.id + @tangerangkota.go.id. 12 tools accept it:
  blueteam_curated_threat_report, blueteam_wazuh_alert_summarize, blueteam_threat_card,
  three_sum_correlation, blueteam_investigate_ip, wazuh_alert_aggregate_analysis,
  wazuh_domain_lookup, wazuh_email_lookup, wazuh_alert_focused_crawl,
  wazuh_alert_timeline, wazuh_attack_velocity, blueteam_wazuh_vulnerabilities.
- TIER 2 — bypass_redaction=true + forensic_token (HUMAN ONLY): raw data to disk via
  blueteam_wazuh_export; the LLM sees only the file path. Requires
  BLUETEAM_ALLOW_FORENSIC_BYPASS=true + BLUETEAM_FORENSIC_TOKEN.
- DEFAULT MODEL = protect_victim: the LLM sees attacker public IPs/payloads/rule/severity/MITRE;
  never internal emails, internal subdomains, private IPs (RFC1918), or internal paths.

LANGKAH 0  — BM25 Prompt Routing (optional):
blueteam_prompt_route(prompt="<isi_prompt>", mode="buckets")

LANGKAH 0a — Index Schema Discovery (REQUIRED before any aggregation):
blueteam_index_schema(fields=["data.srcip","rule.id","rule.groups","agent.name",
  "data.domain","data.url","GeoLocation.city_name"], response_format="json")
→ Wazuh uses string_as_keyword → fields are PLAIN keyword (no .keyword suffix).

LANGKAH 1  — Full overview (all attacks):
blueteam_curated_threat_report(since="24h", investigation_depth="deep",
  response_format="json", redaction_policy="protect_victim")

LANGKAH 1b — Own subdomain/email forensics (TIER 1):
blueteam_wazuh_indexer_search(keyword="tangerangkota.go.id", since="24h",
  redaction_policy="protect_victim", reveal_owned=true, response_format="json")

LANGKAH 2  — Most-attacked subdomains (TIER 1) + asset context:
wazuh_domain_lookup(domain="tangerangkota.go.id", since="24h",
  response_format="json", max_scanned=10000, reveal_owned=true)
→ For each attacked subdomain: blueteam_asset_context(host=<subdomain>, response_format="json")

LANGKAH 3  — Threat card + attack chain per attacker (top 10):
blueteam_threat_card(srcip=<ip>, since="24h")
blueteam_attack_chain(srcip=<ip>, since="24h")

LANGKAH 4  — Sangfor blocklist (BY TIMESTAMP, scoped to report window):
sangfor_blocklist_list(date_start="<24h_ago>", date_end="<now>", response_format="json")
→ For each attacker: sangfor_blocklist_check(ip=<ip>, response_format="json")

LANGKAH 5  — Extract IOCs:
blueteam_extract_iocs(text=<alert_text_from_step_1>)

LANGKAH 6  — Unified threat intel (all providers):
blueteam_threat_intel_aggregate(indicator=<ip>, response_format="json")
argus_ip_lookup(ip=<ip>); netra_ip_analysis(ip=<ip>, response_format="json")
otx_lookup(indicator=<ip>, section="general"); urlhaus_hash_lookup(file_hash=<hash>)

LANGKAH 7  — 3-Sum APT + auto-enrich:
three_sum_correlation(time_window_minutes=1440, follow_up="threat_intel",
  multi_resolution=true, response_format="json", redaction_policy="protect_victim")

LANGKAH 8  — Attack graph + campaign watch:
blueteam_attack_graph(since_days=30, top_n=20, response_format="json")
blueteam_campaign_watch(response_format="json")

LANGKAH 9  — LangGraph investigation (top 10):
blueteam_investigation_workflow(alert_text="<...>", srcip=<ip>, window="24h",
  use_attack_graph=true, generate_report=false, record_verdict=true,
  verdict_label="suspicious")

LANGKAH 10 — LangGraph playbook (if 3-Sum severity ≥ LOW):
blueteam_playbook_run(alert_text="<...>", rule_groups="<...>", window="24h",
  use_attack_graph=true, generate_report=false)

LANGKAH 11 — Compromised emails (locked):
wazuh_compromised_emails_analysis(since="24h", response_format="json")
wazuh_compromised_emails_analysis(since="24h", reveal_owned=true, response_format="json")  # TIER 1

LANGKAH 12 — Semantic search (dominant attack patterns):
blueteam_semantic_search(query="<pattern>", source="alerts", since="24h",
  top_k=30, response_format="json")

LANGKAH 13 — MITRE kill-chain (top 10):
blueteam_stix_killchain(srcip=<ip>, since="24h")

LANGKAH 14 — Geo heatmap:
blueteam_wazuh_geo_heatmap(since="24h", response_format="json")

—— FORMAT MARKDOWN (no OfficeCLI): compose the report directly from steps 1–14.
   Structure: ringkasan → subdomain → IOC → threat intel → 3-Sum → attack graph →
   LangGraph → email locked → semantic → MITRE → geo.

—— FORMAT DOCX (OfficeCLI — install officecli first):
LANGKAH 15 — Generate report:
blueteam_export_report(format="docx",
  title="Laporan Serangan Siber 24 Jam — Infra Pemkot Tangerang",
  path="/var/log/blue-team-mcp/exports/laporan_24jam_{{date}}.docx",
  docx_sections=[...])

LANGKAH 16 — Forensic export (HUMAN ONLY — analyst reads the file on server):
blueteam_wazuh_export(since="24h", bypass_redaction=true,
  forensic_token="<BLUETEAM_FORENSIC_TOKEN>",
  path="/var/log/blue-team-mcp/exports/forensic_24jam_{{date}}.jsonl")

LANGKAH 17 — Webshell check (after analyst reads the export):
cat /var/log/blue-team-mcp/exports/forensic_24jam_*.jsonl | jq -r '.data.url' | sort -u | grep -v '^-$'
→ For each URL: blueteam_check_webshell(url="<url>", timeout=10)
  and urlhaus_lookup(url="<url>", response_format="json")
```

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
