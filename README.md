# Blue Team MCP Server (Wazuh SIEM)

A defensive MCP server for Claude Desktop / any MCP client — the blue-team counterpart to offensive tooling. Exposes **80+ SOC tools** spanning Wazuh SIEM, threat intelligence, alert enrichment, 3-Sum APT correlation, attack graphing, threat hunting, and host forensics.

**Programmer**: `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)

---

## Architecture

```
main.py  ──►  mcp_server/  (package)
                 ├─ core/          HTTP client, redaction, audit, config, attack graph, IOC store
                 ├─ wazuh/         Indexer (OpenSearch) + Manager API (JWT auth)
                 ├─ correlation/   3-Sum engine (pure computation)
                 ├─ threat_intel/  CrowdSec, ThreatFox, OTX, URLhaus, GreyNoise + shared cache
                 ├─ agents/        LangGraph investigation + playbook workflows
                 └─ tools/         44 tool modules (80+ tools)
```

| Transport | Use case |
|-----------|----------|
| `stdio` | Local subprocess / SSH pipe (default) |
| `streamable_http` | Remote HTTP service (`http://<host>:<port>/mcp`) |

---

## Quick Start

```bash
# 1. Clone + install
git clone <repo> && cd Wazuh-MCP-Server
sudo bash setup.sh                    # installs deps, venv, wrapper at /opt/blue-team-mcp

# 2. Configure (edit /opt/blue-team-mcp/config.env)
export WAZUH_INDEXER_URL="https://<host>:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="<indexer-password>"
export WAZUH_API_URL="https://<host>:55000"          # optional — Manager API tools
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="<api-password>"
export OTX_API_KEY="<otx-key>"                       # AlienVault OTX (free)
export URLHAUS_API_KEY="<urlhaus-key>"               # optional — raises rate limit
export CROWDSEC_API_KEY="<crowdsec-key>"             # free tier
export BLUETEAM_CMDB_FILE="/var/log/blue-team-mcp/cmdb_inventory.json"

# 3. Run (stdio — for Claude Desktop via SSH)
mcp-server-blueteam

# or remote HTTP service
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

## Configuration Reference

### Threat Intelligence (all optional — tools degrade gracefully)

| Variable | Default | Notes |
|----------|---------|-------|
| `CROWDSEC_API_KEY` | *(empty)* | free at crowdsec.net |
| `THREATFOX_API_KEY` | *(empty)* | free at threatfox.abuse.ch |
| `OTX_API_KEY` | *(empty)* | free at otx.alienvault.com |
| `URLHAUS_API_KEY` | *(empty)* | optional — raises rate limit |
| `ABUSEIPDB_API_KEY` | *(empty)* | abuseipdb.com |
| `VIRUSTOTAL_API_KEY` | *(empty)* | virustotal.com |
| `NETRA_API_KEY` | *(empty)* | TangerangKota-CSIRT |
| `ARGUS_API_KEY` | *(empty)* | TangerangKota-CSIRT |
| `GREYNOISE_BASE_URL` | `https://api.greynoise.io/v3/community` | no key needed |

### Wazuh SIEM

| Variable | Default | Notes |
|----------|---------|-------|
| `WAZUH_INDEXER_URL` / `_USER` / `_PASSWORD` | *(empty)* | OpenSearch (port 9200) — alert data |
| `WAZUH_API_URL` / `_USER` / `_PASSWORD` | *(empty)* | Manager API (port 55000) — rules/agents/config |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | TLS verification |
| `WAZUH_API_VERIFY_SSL` | `true` | TLS verification |

### Security & Redaction

| Variable | Default | Notes |
|----------|---------|-------|
| `BLUETEAM_REDACTION_POLICY` | `full` | `full` / `protect_victim` / `raw` |
| `BLUETEAM_OWNED_DOMAINS` | *(empty)* | comma-separated, e.g. `tangerangkota.go.id` |
| `BLUETEAM_ALLOW_FORENSIC_BYPASS` | `false` | gate for `raw` policy |
| `BLUETEAM_FORENSIC_TOKEN` | *(empty)* | operator token for forensic export |
| `BLUETEAM_REDACT_*` | `true` | per-layer toggles (email/IP/domain/location/UA) |
| `BLUETEAM_AUDIT_LOG` | *(empty)* | JSONL audit trail |

### Persistence & Limits

| Variable | Default | Notes |
|----------|---------|-------|
| `BLUETEAM_IOC_STORE` | *(empty)* | JSONL IOC lifecycle store |
| `BLUETEAM_IOC_STORE_TTL` | `7776000` | 90d — dead entries pruned |
| `BLUETEAM_ATTACKER_REGISTRY` | *(empty)* | JSONL attacker registry |
| `BLUETEAM_CAMPAIGN_SNAPSHOTS` | *(empty)* | JSONL campaign watch |
| `BLUETEAM_LANGGRAPH_NODE_TIMEOUT` | `120` | per-node timeout (seconds) |
| `BLUETEAM_EXPORT_DIR` | `/var/log/blue-team-mcp/exports` | report/export output |
| `BLUETEAM_CMDB_FILE` | *(empty)* | JSON asset inventory |
| `WAZUH_READ_ONLY` | `false` | skip destructive tools |
| `WAZUH_DISABLED_CATEGORIES` | *(empty)* | comma-separated tool categories to skip |

---

## Available Tools (80+)

### Wazuh SIEM (Indexer + Manager API)

| Tool | Description |
|------|-------------|
| `blueteam_wazuh_indexer_search` | Query OpenSearch for alerts — `search_after` pagination, auto-pagination via `max_scanned` |
| `blueteam_wazuh_alerts` | Local alerts.json reader (fallback) |
| `wazuh_alert_aggregate_analysis` | Zero-doc statistical aggregation (topology/trend/summary) — auto-falls-back to plain `keyword` fields |
| `wazuh_alert_dsl_query` | Raw OpenSearch DSL (size:0 enforced) |
| `wazuh_alert_focused_crawl` | Surgical drill-down into alert clusters |
| `wazuh_domain_lookup` | Search alerts by domain + source IP aggregation |
| `wazuh_email_lookup` | Discover compromised email addresses |
| `wazuh_compromised_emails_analysis` | Correlate emails ↔ attacker IPs (auto-discovers emails) |
| `wazuh_alert_timeline` | `date_histogram` time-bucketed alerts |
| `wazuh_attack_velocity` | Compare two windows for attack acceleration |
| `blueteam_index_schema` | 🆕 Discover field names/types before aggregations (prevents `.keyword` false-negatives) |
| `blueteam_wazuh_geo_heatmap` | Coordinate + city geo heatmap |
| `blueteam_wazuh_vulnerabilities` | CVE findings from vulnerability scanner |
| `blueteam_wazuh_syscheck` | File Integrity Monitoring events |
| `blueteam_wazuh_compliance` | CIS / PCI DSS / GDPR / HIPAA / NIST summaries |
| `blueteam_wazuh_get_rules` / `_decoders` / `_groups` / `_security_events` / `_cluster_nodes` | Manager API (JWT) |
| `blueteam_wazuh_agents` / `_agents_summary` / `_manager_logs` | Agent inventory + manager logs |

### 3-Sum APT Detection

| Tool | Description |
|------|-------------|
| `three_sum_correlation` | Engine A (weighted multi-IoC intersection) + Engine B (volumetric Z-score, MAD + shoulder-check) + multi-resolution (1h/24h/7d) + Indexer degradation detection |

### Threat Intelligence (7 providers + unified aggregator)

| Tool | Description |
|------|-------------|
| `blueteam_threat_intel_aggregate` | 🆕 One call → CrowdSec + ThreatFox + OTX + GreyNoise + AbuseIPDB + VirusTotal concurrently |
| `crowdsec_ip_reputation` / `_bulk` | CrowdSec CTI reputation |
| `threatfox_ioc_search` / `_bulk` | abuse.ch IOC search (malware families) |
| `otx_lookup` / `_bulk` | AlienVault OTX — pulses, adversaries, MITRE |
| `urlhaus_lookup` / `_bulk` | URLhaus malware URL database |
| `urlhaus_hash_lookup` | URLhaus payload lookup (malware signature from hash) |
| `greynoise_ip_context` | Scanner vs business service (no key) |
| `argus_ip_lookup` | TangerangKota-CSIRT Argus (7-source aggregation) |
| `netra_ip_analysis` | Netra threat score + AI insight |
| `blueteam_unified_threat_score` | Weighted multi-source confidence (0–1) |

### Alert Enrichment

| Tool | Description |
|------|-------------|
| `blueteam_wazuh_alert_summarize` | IoC extraction + rule grouping + MITRE digest |
| `blueteam_beacon_detect` | C2 beaconing (CV < 0.35) with `BLUETEAM_BEACON_EXCLUDE_IPS` |
| `blueteam_attack_chain` | Rule-to-rule kill-chain transitions |
| `blueteam_threat_card` | Single-call report: alerts + intel + MITRE |
| `blueteam_wazuh_alert_compare` | Side-by-side IP comparison |
| `blueteam_curated_threat_report` | 29-dimension filter→aggregate→enrich pipeline |

### Investigation & Correlation

| Tool | Description |
|------|-------------|
| `blueteam_investigate_ip` | One-call IP triage (profile + timeline + geo) |
| `blueteam_mark_investigated` | Record verdict (true_positive/false_positive/…) |
| `blueteam_false_positive_tracker` | Rule-level FP counting |
| `blueteam_investigation_summary` / `_history` | Investigation dashboard + history |
| `blueteam_asset_context` | 🆕 CMDB asset lookup (criticality, owner) |
| `blueteam_check_webshell` | 🆕 curl + 20-signature webshell scan |
| `blueteam_prompt_route` | 🆕 BM25 prompt-to-tool routing |

### Graph Engineering (networkx) & LangGraph

| Tool | Description |
|------|-------------|
| `blueteam_attack_graph` | Co-occurrence clusters, hub/bridge/edge-betweenness centrality, suspicion rank (PageRank) |
| `blueteam_campaign_watch` | Campaign snapshot diff (new clusters, growth) |
| `blueteam_ioc_lifecycle` | Time-decayed IOC store (TTL + decay eviction) |
| `blueteam_stix_killchain` | ATT&CK kill-chain per srcip |
| `blueteam_baseline_drift` | Z-score baseline drift detection |
| `blueteam_investigation_workflow` | LangGraph: extract→enrich→correlate→analytics(graph∥killchain)→baseline→verdict |
| `blueteam_playbook_run` | Alert-driven playbook with 3-template retry ladder |

### Domain & Host Forensics

| Tool | Description |
|------|-------------|
| `blueteam_whois_lookup` / `blueteam_crtsh_lookup` | RDAP + certificate transparency |
| `blueteam_semantic_search` | BM25 over Wazuh rules/alerts |
| `blueteam_extract_iocs` | Extract IP/domain/URL/email/hash from text |
| `blueteam_wazuh_export` | Server-side JSONL export (scroll API) + forensic bypass |
| `blueteam_export_report` | Generate .docx/.xlsx/.pptx via officecli |
| Host forensics (26 tools) | log readers, fail2ban, rootkit scan, lynis, process/cron, users |
| `sangfor_blocklist_check` / `_list` | Sangfor firewall blocklist (with `date_start`/`date_end` timestamp filter) |

---

## Security & Privacy — Two-Tier Unmasking

`redaction_policy="protect_victim"` is the default: **attacker PII stays visible** (public IPs, exploit payloads), **own PII stays masked** (internal emails/subdomains/private IPs).

| Tier | Flag | Reveals | Who |
|------|------|---------|-----|
| **1 — Owned reveal** | `reveal_owned=true` | Only `*.tangerangkota.go.id` + `@tangerangkota.go.id` | LLM (safe — your own data) |
| **2 — Full raw** | `bypass_redaction=true` + `forensic_token` | Everything raw | Human operator only (never LLM) |

**Tier 1 tools** (accept `reveal_owned`): `blueteam_curated_threat_report`, `blueteam_wazuh_alert_summarize`, `blueteam_threat_card`, `three_sum_correlation`, `wazuh_alert_aggregate_analysis`, `wazuh_domain_lookup`, `wazuh_email_lookup`, `wazuh_compromised_emails_analysis`, `wazuh_alert_focused_crawl`, `blueteam_wazuh_geo_heatmap`, `wazuh_alert_timeline`, `wazuh_attack_velocity`.

**Tier 2** (`blueteam_wazuh_export` with `bypass_redaction=true` + `forensic_token`): writes raw data **directly to disk** — the LLM only receives the file path, never the raw content. Requires `BLUETEAM_ALLOW_FORENSIC_BYPASS=true` + `BLUETEAM_FORENSIC_TOKEN`.

---

## SOC Daily Report Prompt

### Format DOCX (via OfficeCLI)

```
⚠️ EXECUTION RULES:
- redaction_policy="protect_victim" HANYA diterima oleh 5 tool:
    blueteam_curated_threat_report, blueteam_wazuh_alert_summarize,
    blueteam_wazuh_indexer_search, three_sum_correlation,
    blueteam_investigate_ip
- blueteam_wazuh_export pakai bypass_redaction (bukan redaction_policy).
- reveal_owned=true HANYA pada 12 tool Tier 1 (lihat daftar di atas).
- blueteam_export_report HANYA format docx/xlsx/pptx; path wajib /var/log/blue-team-mcp/exports/.

LANGKAH 0  — BM25 Prompt Routing (opsional):
blueteam_prompt_route(prompt="<isi_prompt>", mode="buckets")

LANGKAH 0a — Index Schema Discovery (WAJIB sebelum aggregation):
blueteam_index_schema(fields=["data.srcip","rule.id","rule.groups","agent.name",
  "data.domain","data.url","GeoLocation.city_name"], response_format="json")
→ Wazuh pakai string_as_keyword → field PLAIN keyword (TANPA .keyword suffix).

LANGKAH 1  — Gambaran Menyeluruh:
blueteam_curated_threat_report(since="24h", investigation_depth="deep",
  response_format="json", redaction_policy="protect_victim")

LANGKAH 1b — Forensik Subdomain & Email (reveal_owned — TIER 1):
blueteam_wazuh_indexer_search(keyword="tangerangkota.go.id", since="24h",
  redaction_policy="protect_victim", reveal_owned=true, response_format="json")

LANGKAH 2  — Subdomain Paling Diserang + Asset Context:
wazuh_domain_lookup(domain="tangerangkota.go.id", since="24h",
  response_format="json", max_scanned=10000, reveal_owned=true)
→ Untuk tiap subdomain: blueteam_asset_context(host=<subdomain>)

LANGKAH 3  — Threat Card + Attack Chain per Attacker (top 10):
blueteam_threat_card(srcip=<ip>, since="24h")
blueteam_attack_chain(srcip=<ip>, since="24h")

LANGKAH 4  — Sangfor Blocklist (BY TIMESTAMP):
sangfor_blocklist_list(date_start="<24jam_lalu>", date_end="<sekarang>", response_format="json")
→ Untuk tiap attacker: sangfor_blocklist_check(ip=<ip>, response_format="json")

LANGKAH 5  — Ekstrak IOC:
blueteam_extract_iocs(text=<alert_text_dari_langkah_1>)

LANGKAH 6  — Unified Threat Intel (SEMUA provider):
Untuk tiap attacker IP + hash:
  blueteam_threat_intel_aggregate(indicator=<ip>, response_format="json")
  argus_ip_lookup(ip=<ip>)
  netra_ip_analysis(ip=<ip>, response_format="json")
  otx_lookup(indicator=<ip>, section="general")
  urlhaus_hash_lookup(file_hash=<hash>)

LANGKAH 7  — 3-Sum APT + ThreatFox:
three_sum_correlation(time_window_minutes=1440, follow_up="threat_intel",
  multi_resolution=true, response_format="json", redaction_policy="protect_victim")

LANGKAH 8  — NetworkX Attack Graph:
blueteam_attack_graph(since_days=30, top_n=20, response_format="json")
blueteam_campaign_watch(response_format="json")

LANGKAH 9  — LangGraph Investigation (top 5 attacker):
blueteam_investigation_workflow(alert_text="<...>", srcip=<ip>,
  window="24h", use_attack_graph=true, record_verdict=true, verdict_label="suspicious")

LANGKAH 10 — LangGraph Playbook (jika anomali):
blueteam_playbook_run(alert_text="<...>", rule_groups="<...>", window="24h")

LANGKAH 11 — Email Locked + Analisa:
wazuh_compromised_emails_analysis(since="24h", reveal_owned=true, response_format="json")

LANGKAH 12 — Semantic Search (pola dominan):
blueteam_semantic_search(query="<pola>", source="alerts", since="24h", top_k=30)

LANGKAH 13 — MITRE ATT&CK (top 5):
blueteam_stix_killchain(srcip=<ip>, since="24h")

LANGKAH 14 — Geo Heatmap:
blueteam_wazuh_geo_heatmap(since="24h", response_format="json")

LANGKAH 15 — Laporan Akhir (DOCX):
blueteam_export_report(format="docx",
  title="Laporan Serangan Siber 24 Jam — Infra Pemkot Tangerang",
  path="/var/log/blue-team-mcp/exports/laporan_24jam_{{date}}.docx",
  docx_sections=[...])

LANGKAH 16 — Forensic Export (HUMAN ONLY):
blueteam_wazuh_export(since="24h", bypass_redaction=true,
  forensic_token="<TOKEN_OPERATOR>", path="/var/log/.../forensic_24jam.jsonl")

LANGKAH 17 — Webshell Check + URLhaus:
blueteam_check_webshell(url=<url>, timeout=10)
urlhaus_lookup(url=<url>, response_format="json")
```

### Format Markdown (tanpa OfficeCLI)

Jalankan LANGKAH 1-14 yang sama, lalu LLM menyusun markdown langsung dengan struktur laporan (ringkasan → subdomain → IOC → threat intel → 3-Sum → attack graph → LangGraph → email locked → semantic → MITRE → geo → webshell).

---

## Example Prompts

```
"Investigate this IP comprehensively."
→ blueteam_investigate_ip(srcip="103.166.210.53", since="24h")

"Run 3-Sum APT detection for the last 24h."
→ three_sum_correlation(time_window_minutes=1440, follow_up="threat_intel", multi_resolution=true)

"Aggregate threat intel for 140.82.0.86 from all providers."
→ blueteam_threat_intel_aggregate(indicator="140.82.0.86")

"Check if this URL is a known malware distributor."
→ urlhaus_lookup(url="http://evil.com/malware.exe")

"Discover the field mapping before querying."
→ blueteam_index_schema(fields=["rule.id","agent.name","data.srcip"])

"Analyze the attack graph for campaign clusters."
→ blueteam_attack_graph(since_days=30, top_n=20)

"Run an automated investigation workflow."
→ blueteam_investigation_workflow(srcip="140.82.0.86", window="24h", use_attack_graph=true)

"What is this asset, and how critical?"
→ blueteam_asset_context(host="ppid.tangerangkota.go.id")

"Check a suspicious URL for webshell."
→ blueteam_check_webshell(url="https://ppid.tangerangkota.go.id/uploads/shell.php")
```

---

## Requirements

- Python 3.11+
- `mcp`, `httpx[http2]`, `pydantic`, `networkx`, `langgraph`, `officecli-sdk`
- See `requirements.txt` for the full pinned list.

---

## Development Guardrails

- `python3 check_guardrails.py --strict` must pass (exit 0) before merge.
- All tools annotate `readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint` explicitly.
- Logging → stderr only (stdout is the JSON-RPC channel for stdio).
- Pure-computation modules (`three_sum_core.py`) stay stdlib-only.
