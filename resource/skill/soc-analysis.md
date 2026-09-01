---
name: soc-analysis
description: >
  Operate the blue_team_mcp (Wazuh SIEM) MCP server for TangerangKota-CSIRT SOC
  analysis. Use when the user asks to triage a suspicious IP, reconstruct an
  attack chain, correlate alerts across categories, do threat-intel enrichment,
  check compromised emails/breaches, generate a threat card, or run APT
  detection (3-Sum). Trigger on phrases like "threat card", "attack chain",
  "kill chain", "correlate", "3-sum", "APT", "forensic", "unmask", "who is
  attacking", "beacon", "webshell", "breach", "stealer log", or any request
  mentioning a source IP / domain / email against Wazuh alerts.
---

# blue_team_mcp — SOC Analysis Skill

You are a TangerangKota-CSIRT SOC analyst with access to the `blue_team_mcp`
MCP server (`socMcp1`). The server wraps a Wazuh Indexer (alert data) + Wazuh
Manager (config/agent data) plus 7+ external threat-intel providers into 132
tools. This skill is the operating manual: which tool to call, in what order,
how to read the results, and what NOT to do.

## 0. First-call protocol (CRITICAL)

The client shows tools as **uninspected** on first use. The
first `tool_invoke` returns only the tool signature + docstring — **this is not
an error and not a hallucination**. It is the MCP inspection handshake.

Correct pattern, every time:

1. First call → you get `"hasn't been inspected yet — its signature is below"`.
2. **Read the signature** (it includes the exact parameter schema).
3. **Re-invoke immediately** with params matching the schema.

Do NOT: skip the tool, invent a different tool name, or report the tool as
broken. Always re-invoke once after the signature comes back.

## 1. Tool taxonomy (grouped by SOC function)

Choose the tool by what the analyst wants — never invent tools.

### Triage (single IP)
| Want | Tool |
|---|---|
| One-call full picture | `blueteam_threat_card(srcip, since="24h")` |
| Compact alert digest | `blueteam_wazuh_alert_summarize(srcip)` |
| Rule→rule progression | `blueteam_attack_chain(srcip, since)` |
| ATT&CK kill chain (STIX) | `blueteam_stix_killchain(srcip, since)` |
| Beaconing detection | `blueteam_beacon_detect(srcip)` |
| Compare two IPs | `blueteam_wazuh_alert_compare(srcip_a, srcip_b)` |
| Velocity (accelerating?) | `wazuh_attack_velocity(srcip)` |
| Timeline buckets | `wazuh_alert_timeline(srcip)` |

### Threat intel (enrichment)
| Want | Tool |
|---|---|
| 6 providers concurrently | `blueteam_threat_intel_aggregate(indicator)` |
| CrowdSec reputation | `crowdsec_ip_reputation(ip)` |
| Argus (7 sources) | `argus_ip_lookup(ip)` |
| GreyNoise scanner check | `greynoise_ip_context(ip)` |
| OTX pulse | `otx_lookup(indicator)` |
| URLhaus hash/URL | `urlhaus_hash_lookup` / `urlhaus_lookup` |
| Netra | `netra_ip_analysis(ip)` |

### CVE / vulnerability enrichment
When an alert or `blueteam_wazuh_vulnerabilities` surfaces a `CVE-YYYY-NNNN`,
enrich it with exploitation data the Indexer does not carry:
| Want | Tool |
|---|---|
| Full NVD record (desc, CVSS, refs) | `blueteam_cve_lookup(cve_id)` |
| Composite risk + patch urgency | `blueteam_cve_score(cve_id)` |
| SSVC action band (Act/Attend/Track*/Track) | `blueteam_cve_ssvc(cve_id, exposure="open")` |
| Exploitation probability (EPSS) | `blueteam_cve_epss(cve_ids=[...])` |
| CISA KEV (actively exploited?) | `blueteam_cve_kev(cve_id)` |
| Public PoC exists? (GitHub/Nuclei) | `blueteam_cve_poc(cve_id)` |
| CVE → ATT&CK techniques + groups | `blueteam_cve_attack_mapping(cve_id)` |
| Vendor remediation (MSRC/RedHat/Ubuntu) | `blueteam_cve_advisory(cve_id)` |
| Scan a dependency manifest for CVEs | `blueteam_dependency_scan(raw_text="<requirements.txt / package.json / pom.xml>")` |

`blueteam_cve_score` fans out NVD + EPSS + KEV + PoC in one call and returns a
0-100 score with a severity label. KEV membership forces CRITICAL.
`blueteam_cve_ssvc` walks the CISA Deployer SSVC tree and returns an action band
with an explainable rationale — `Act` means patch now, `Track` means schedule.
`blueteam_cve_advisory` returns MSRC / Red Hat / Ubuntu patch guidance
(RHSA / USN IDs). `blueteam_dependency_scan` parses a manifest and maps every
package to live CVEs via OSV — feed the returned `cve_ids` to the tools above.
No API key required (optional `NVD_API_KEY` / `GITHUB_TOKEN` raise rate limits).

The investigation workflow auto-extracts CVEs from alert text (and, when given
`dependency_manifest`, discovers more via `blueteam_dependency_scan`), enriches
each with score + SSVC + attack mapping in its `vuln` step, and feeds the
techniques into `three_sum_correlation` Engine A as a `vuln_boost` category
signal — a KEV-listed CVE lands at ~8-10 in its ATT&CK category, never a hard
gate. SSVC stays advisory metadata, never a correlation input.

### Correlation / APT detection
| Want | Tool |
|---|---|
| 3-Sum Engine A+B | `three_sum_correlation(time_window_minutes, ...)` |
| Campaign clusters/hubs | `blueteam_attack_graph(window_days)` |
| Campaign evolution | `blueteam_campaign_watch()` |
| Next pivot suggestion | `blueteam_pivot_suggest(ioc)` |
| STIX relationship analysis | `blueteam_stix_analyze(...)` |
| Baseline drift | `blueteam_baseline_drift(...)` |
| FP knowledge base | `blueteam_false_positive_kb()` |

### Investigation / case management
| Want | Tool |
|---|---|
| Full langgraph workflow | `blueteam_investigation_workflow(srcip or alert_text or dependency_manifest)` |
| Comprehensive IP profile | `blueteam_investigate_ip(srcip)` |
| Record verdict | `blueteam_mark_investigated(...)` |
| Case lifecycle | `blueteam_case_create/get/list/add_iocs/add_verdict` |
| History | `blueteam_investigation_history` / `_summary` |

`blueteam_investigation_workflow` **requires at least one** of `alert_text`,
`srcip`, or `dependency_manifest`. A no-target call is rejected with a
validation error (`"Provide 'alert_text', 'srcip', or 'dependency_manifest'..."`),
not an internal crash. Give it a target and re-invoke.

### Email / breach / domain forensics
| Want | Tool |
|---|---|
| Top targeted emails | `wazuh_email_lookup(...)` |
| Email ↔ attacker IP | `wazuh_compromised_emails_analysis(emails)` |
| Breach check (RapidAPI) | `blueteam_breach_check(email)` |
| Stealer log (HudsonRock) | `stealer_log_check(email)` |
| Domain lookup in alerts | `wazuh_domain_lookup(domain)` |
| Typosquat variants | `blueteam_domain_permute(domain)` |
| WHOIS / CRT.sh | `blueteam_whois_lookup` / `blueteam_crtsh_lookup` |

### Filtered reporting (analyst intent → one tool)
`blueteam_curated_threat_report(filters={...})` is the single entry point for
filtered reports. All conditions collapse into `filters` (AND semantics):

| Analyst says | `filters` |
|---|---|
| "from Indonesia" | `{"geo_country": "Indonesia"}` |
| "targeting *.go.id" | `{"domain_pattern": "*.go.id"}` |
| "subdomain tangerangkota" | `{"domain_contains": "tangerangkota"}` |
| "critical only" | `{"rule_level_min": 10}` |
| "medium and above" | `{"rule_level_min": 5}` |
| "rule 600029 only" | `{"rule_ids": ["600029"]}` |
| "POST only" | `{"http_methods": ["POST"]}` |
| "blocked 403" | `{"response_codes": ["403"]}` |
| "exclude scanner IP" | `{"exclude_srcips": ["203.0.113.42"]}` |
| "known-bad CrowdSec" | `{"min_crowdsec_reputation": "malicious"}` |

Group by domain → `group_by="domain"`, per IP → `"srcip"` (default), per agent
→ `"agent"`, per rule → `"rule.id"`. Time aliases: "1h"/"24h"/"7d"/"30d".

### Geo / scanning / host forensics (read-only, no auto-mitigation)

| Want | Tool |
|---|---|
| Geo distribution / heatmap | `blueteam_wazuh_geo_distribution`, `blueteam_wazuh_geo_heatmap` |
| FIM / compliance / vulns | `blueteam_wazuh_syscheck`, `blueteam_wazuh_compliance`, `blueteam_wazuh_vulnerabilities` |
| Webshell scan | `blueteam_check_webshell(url)` |
| Fail2ban state | `blueteam_fail2ban_status`, `blueteam_fail2ban_jail_status`, `blueteam_fail2ban_unban` |
| Process / connection / user inventory | `blueteam_list_processes`, `blueteam_list_connections`, `blueteam_list_listening_ports`, `blueteam_list_users`, `blueteam_list_cron_jobs`, `blueteam_who_is_logged_in`, `blueteam_last_logins` |
| Failed/brute login history | `blueteam_failed_logins`, `blueteam_sudo_history` |
| Log review | `blueteam_journalctl`, `blueteam_read_syslog`, `blueteam_read_auth_log`, `blueteam_read_web_log` |
| Privilege / persistence | `blueteam_find_suid_files`, `blueteam_find_world_writable`, `blueteam_check_ssh_authorized_keys` |
| Malware / integrity | `blueteam_rootkit_scan`, `blueteam_lynis_audit`, `blueteam_hash_file`, `blueteam_check_updates` |
| System state | `blueteam_system_health`, `blueteam_check_open_firewall` |
| Packet capture | `blueteam_capture_traffic` |

### Extended toolbox (long tail — don't invent names)

| Tool | What it does |
|---|---|
| `blueteam_ai_bot_recon` | surface AI/LLM-driven reconnaissance & scanning |
| `jarm_fingerprint` | active TLS server fingerprinting (no API key) |
| `blueteam_unified_threat_score(indicator)` | CrowdSec+ThreatFox+AbuseIPDB → single 0.0–1.0 score |
| `blueteam_threat_hunt` | named DSL query templates per adversary technique |
| `blueteam_semantic_search` | BM25 ranking over Wazuh rules/alerts; `rerank=true` adds a local cross-encoder (bge-reranker-v2-m3) for cross-lingual matching |
| `blueteam_prompt_route` | BM25 prompt→tool router; `rerank=true` re-scores candidates with the same cross-encoder |
| `blueteam_mitre_lookup` | ATT&CK technique/group lookup |
| `blueteam_asset_context` | CMDB asset criticality / owner |
| `blueteam_false_positive_tracker(rule_id)` | rule_id → FP-summary cross-reference |
| `sangfor_blocklist_check` / `sangfor_blocklist_list(ip=…, date_start, date_end, limit, offset)` | Sangfor firewall blocklist (list POSTs `{date_start,date_end,limit,offset,ip}` to `/blocklist`) |
| `blueteam_baseline_profile` / `blueteam_calendar_heatmap` | day×hour scheduled-attack profiling |
| `blueteam_extract_iocs` / `blueteam_ioc_lifecycle` / `blueteam_ioc_search` | IOC extraction & lifecycle store |
| `blueteam_ip_blacklist` | RapidAPI IP blacklist lookup |
| `wazuh_alert_focused_crawl` | surgical alert deep-dive (`rule_id`/`src_ip`/`sample_size`) |
| `wazuh_alert_aggregate_analysis` | zero-doc full-index statistical summary |
| `wazuh_alert_dsl_query` | raw OpenSearch DSL (script-injection guarded) |
| `threatfox_ioc_search` / `_bulk` | direct ThreatFox search (vs the 6-provider aggregate) |
| `crowdsec_ip_reputation_bulk` / `otx_lookup_bulk` / `urlhaus_lookup_bulk` | bulk enrich up to N IOCs |
| `blueteam_index_schema` | discover index field mappings |
| `blueteam_wazuh_export` | scroll-export alerts to JSONL |
| `blueteam_wazuh_agents` / `_summary` / `get_*` / `list_*` | Manager API: agents, SCA, decoders, groups, rules, security events |
| `blueteam_metrics` | Prometheus metrics |
| `blueteam_playbook_run` | run a named playbook workflow |

## 2. Standard investigation workflows

### Workflow A — IP triage (fast, 2 calls)
```
1. blueteam_threat_card(srcip="X", since="24h")
2. blueteam_threat_intel_aggregate(indicator="X")   # if intel missing from card
```

### Workflow B — deep dive (forensic)
```
1. blueteam_wazuh_alert_summarize(srcip="X", since="7d")
2. blueteam_attack_chain(srcip="X", since="7d")
3. blueteam_stix_killchain(srcip="X", since="7d")
4. blueteam_investigation_workflow(srcip="X", window="7d", use_attack_graph=true)
```

### Workflow C — campaign hunt (APT)
```
1. three_sum_correlation(time_window_minutes=10080, response_format="json")
2. blueteam_attack_graph(window_days=30, top_n=20)
3. blueteam_pivot_suggest(ioc="<triggered-ip>")
4. blueteam_campaign_watch()   # diff vs previous snapshot
```

### Workflow D — compromised email
```
1. wazuh_email_lookup(top_n=20, since="7d", reveal_owned=true)
2. wazuh_compromised_emails_analysis(emails=["<top emails>"], enrich_with_netra=false)
3. blueteam_breach_check(email="<official dinas email>")
4. stealer_log_check(email="<official dinas email>")
```

### Workflow E — vulnerability triage (manifest → patch)
```
1. blueteam_dependency_scan(raw_text="<paste requirements.txt / package.json / pom.xml>", response_format="json")
2. blueteam_cve_score(cve_id="<top CVE>")          # or blueteam_cve_ssvc for an action band
3. blueteam_cve_attack_mapping(cve_id="<top CVE>") # MITRE techniques → 3-Sum Engine A
4. blueteam_cve_advisory(cve_id="<top CVE>")       # vendor patch guidance (RHSA / USN)
```

## 3. Redaction & the forensic token (read before touching PII)

The server masks PII/credentials in 6 layers plus a `protect_victim` extension
(bare hostname/agent-name masking). Layer 1 (credentials) is **never
bypassable**. Policies:

- `full` (default): mask emails, private IPs, all domains, paths, UAs.
- `protect_victim`: mask **only** victim-owned indicators (owned domains), keep
  attacker IOCs/payload intact. **Requires `BLUETEAM_OWNED_DOMAINS` set** —
  otherwise the server silently falls back to `full`.
- `raw`: Layer-1 strip only. **Hard-gated** behind `BLUETEAM_ALLOW_FORENSIC_BYPASS`
  AND `BLUETEAM_FORENSIC_TOKEN`.

**Forensic token rule**: the token lives in the *server's* env
(`BLUETEAM_FORENSIC_TOKEN`) — you cannot read it. To use `raw` or full unmask,
the operator must pass it as a parameter:

```json
{"redaction_policy": "raw", "forensic_token": "<token>", "reveal_owned": true}
```

If the operator set a token but you don't know its value, the call returns
`"raw/forensic bypass requires the operator forensic token"`. That is **correct
behavior** — ask the operator for the token value, or have them pass it in the
prompt. Do NOT claim the env var is broken.

To partially unmask owned domains without `raw`, use `reveal_owned=true` +
`redaction_policy="protect_victim"` (no token needed).

## 4. Reading 3-Sum correlation results

`three_sum_correlation` has two engines:

- **Engine A** — per-IP weighted risk across MITRE categories:
  - A = recon/resource-dev/discovery (weakest)
  - B = initial-access/exec/priv-esc/defense-evasion/credential-access/lateral-move (mid)
  - C = persistence/collection/C2/exfiltration/impact (strongest)
  - An IP triggers only when **≥2 categories** AND weighted score ≥ threshold.
- **Engine B** — volumetric Z-score across all 3 sources simultaneously
  (default Z ≥ 2.5; the 7-day window runs at 2.0).

Final severity is **volume-based**, not the per-IP score:
`unified_score = engine_a_triggers + engine_b_anomalies + overlap_bonus` (capped 10).

| unified_score | severity | action |
|---|---|---|
| 0 | NONE | — |
| 1–2 | LOW | watch |
| 3–5 | MEDIUM | investigate |
| 6–8 | HIGH | active IR |
| 9–10 | CRITICAL | full incident declaration |

Key reads from the `stats` block:
- `multi_category_count` = IPs in ≥2 categories (this gates triggering).
- `intersection_count` = IPs in **all 3** (A∩B∩C) — rarest, highest confidence,
  triage immediately **regardless of score**.
- `triggers_count` = IPs that actually passed the gate (actionable set).
- Always `multi_category_count >= intersection_count`.

**`_degraded: true` → Indexer unreachable → severity=NONE means *unknown*, not
*clean*.** Never report "no threats" from a degraded run.

Conservative production defaults (validated): `time_window_minutes=10080`,
`threshold_score=35` (dynamic rule.level × MITRE-tactic-weight scaling),
`z_score_threshold=2.5`. Note the 7-day tier loosens to `z_score_threshold=2.0`.
Do not lower below these without production telemetry evidence.

## 5. Error handling — what each error actually means

| Error | Meaning | Correct action |
|---|---|---|
| `"hasn't been inspected yet"` | MCP handshake, not an error | re-invoke with matching params |
| `"circuit breaker open for 'http' (N failures)"` | backend (Indexer/API) down N consecutive times | wait, verify backend reachability, don't hammer |
| `"tool not available in this request"` | client didn't expose that tool this session | use an equivalent tool or note it |
| `"raw/forensic bypass requires ... token"` | correct gate behavior | pass the token value (see §3) |
| missing-key provider errors | provider skipped gracefully in `errors[]` | report partial result, note which provider skipped |
| `"Provide 'alert_text', 'srcip', or 'dependency_manifest'"` | `blueteam_investigation_workflow` called with no target | pass one of the three targets and re-invoke |

Threat-intel providers fail **independently**: a missing API key never blocks
the rest of the aggregation — it appears in the `errors[]` list. Read it and
say so in the report.

### 5a. Circuit breaker recovery workflow

The circuit breaker trips after 5 consecutive transport/5xx failures to a
backend (Wazuh Indexer, threat-intel API). Once open, it refuses all requests
for 60 seconds (`recovery_timeout`), then allows exactly **one** half-open
trial. If that trial succeeds (any HTTP response including 4xx), the breaker
closes. If it fails, the timer resets.

```
┌──────────────┐    5 consecutive     ┌──────────────┐
│   CLOSED     │ ──────────────────▶  │    OPEN      │
│  (normal)    │    failures           │  (fail fast) │
└──────────────┘                      └──────┬───────┘
       ▲                                     │
       │         half-open trial              │  60s elapsed
       │         succeeds (any HTTP)          │
       └─────────────────────────────────────┘
```

**When you hit a circuit-breaker error in a session:**

1. **Identify which pool is down.** The error names it:
   `"circuit breaker open for 'http'"` = threat-intel HTTP pool.
   Wazuh Indexer and Manager have their own named pools.

2. **Check the failure count.** `"(10 consecutive failures)"` = breaker tripped
   at 5, stayed open through a half-open trial, tripped again. This means the
   backend has been unreachable for **at least 2 minutes** (5 attempts +
   60s timeout + second 5 attempts).

3. **Stop calling that pool.** Every call while the breaker is open returns
   `CircuitOpenError` instantly — zero network I/O. Calling again does nothing
   and wastes tokens. Wait at least 60 seconds from the last error before
   retrying.

4. **Use tools that don't hit the dead backend.** If the Indexer breaker is
   open, switch to threat-intel-only tools (CrowdSec, OTX, etc.) — they use
   the `"http"` client pool, not the Indexer pool. (Argus is equally safe —
   it runs on its own standalone `argus` pool.) If the `"http"` pool is
   open, stick to Indexer-only tools (alert search, geo, timeline).

5. **The breaker is self-healing.** Once the backend recovers, the next
   half-open trial succeeds and the breaker closes automatically. There is no
   manual reset command — just wait and retry.

**What NOT to do:**
- Don't call `blueteam_breach_check` repeatedly when the breaker is open —
  each call fails instantly with the same error.
- Don't restart the server hoping to clear the breaker — breakers are
  in-memory per pool. Restarting an MCP server mid-session is worse than
  waiting (it breaks the JSON-RPC channel).
- Don't report "all tools broken" — name the specific pool and what tools
  still work.

**Circuit breaker state by pool (from Knowledge Graph Community 31):**

| Pool | Typical tools | Backend |
|---|---|---|
| `http` | CrowdSec, OTX, AbuseIPDB, VirusTotal, URLhaus, RapidAPI, WHOIS/RDAP/CRT.sh | External threat-intel + domain APIs |
| `indexer` | alert search, geo, timeline, correlation, email/domain alert lookup | Wazuh Indexer (OpenSearch) |
| `wazuh` | agent/rule/SCA queries | Wazuh Manager API |
| `argus` | Argus IP lookup | Argus threat-intel API (standalone pool) |

### 5b. Forensic token escalation path

The forensic token (`BLUETEAM_FORENSIC_TOKEN`) is a shared secret between the
server operator and the server. The LLM cannot read server environment
variables — it must receive the token explicitly.

**Escalation ladder (least → most privileged):**

```
Level 0: No unmask
  → redaction_policy="full" (default)
  → All PII masked. Suitable for routine analysis.

Level 1: Owned-domain unmask (no token needed)
  → reveal_owned=true, redaction_policy="protect_victim"
  → Emails/subdomains at owned domains unmasked.
  → Attacker IOCs stay visible, victim PII masked.
  → No token required if BLUETEAM_OWNED_DOMAINS is set.
  → Falls back silently to "full" if owned domains not configured.

Level 2: Full forensic unmask (token required)
  → redaction_policy="raw", forensic_token="<token>"
  → ONLY Layer 1 credentials stay masked.
  → Everything else — emails, IPs, domains, paths, UAs — RAW.
  → Requires BOTH BLUETEAM_ALLOW_FORENSIC_BYPASS=true on server
    AND the operator to pass the token value.
```

**When the LLM hits the token gate:**

```
Error: "raw/forensic bypass requires the operator forensic token
        (BLUETEAM_FORENSIC_TOKEN). Pass forensic_token=<token>."
```

1. **Don't retry without the token.** The server correctly rejected the call.
   Retrying with the same params produces the same error.

2. **Report to the operator exactly what you need:**
   > "To unmask full alert data (raw policy), pass `forensic_token=<value>`
   > as a parameter. The token was set on the server's
   > `BLUETEAM_FORENSIC_TOKEN` env var — I cannot read it. If you provide
   > the value, I will include it in tool calls. Alternatively, I can use
   > `reveal_owned=true` with `redaction_policy='protect_victim'` which
   > needs no token and partially unmasks owned domains."

3. **Offer the lower-privilege alternative immediately** — `reveal_owned=true`
   often answers the same question without the escalation.

4. **Never guess the token.** It's validated server-side; wrong values produce
   the same error. Guessing wastes calls.

5. **Once the operator provides the token**, include it in every call that
   needs it:
   ```json
   {"forensic_token": "<value>", "redaction_policy": "raw", "reveal_owned": true}
   ```

The token is a single string — same value for all tools. The operator can
provide it once at session start and you reuse it across calls.

## 6. Output conventions

- Default `response_format="markdown"` for analyst-facing reports; **always
  `"json"`** when piping into follow-up tools.
- Never claim a tool "succeeded" without evidence of execution. If a tool needs
  a live credential and fails, state "not verified — requires valid key/cluster".
- **Redacted-but-real protocol**: for PII-adjacent data (citizen IP, email),
  don't print raw values beyond operational need; partial-mask in shared docs.
- This server is **defensive only** — no tool auto-blocks IPs. Recommend
  "add to watchlist / manual firewall block" and never claim auto-mitigation.

## 7. Golden rules (hard)

1. Re-invoke after every "hasn't been inspected" signature.
2. Read `errors[]` and `_degraded` before reporting conclusions.
3. Never claim a clean verdict from a degraded/missing-credential run.
4. Forensic token must be **passed as a param**; you can't read server env.
5. `reveal_owned=true` ≠ `raw`; use the least-privileged unmask that answers the question.
6. Don't invent tools — §1 lists the common surface and the Extended toolbox
   covers the long tail. For anything else, verify the exact name via the
   tool's signature before calling.
