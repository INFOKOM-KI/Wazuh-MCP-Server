---
name: soc-analysis
description: >
  Operate the blue_team_mcp (Wazuh SIEM) MCP server for TangerangKota-CSIRT SOC
  analysis. Use when the user asks to triage a suspicious IP, reconstruct an
  attack chain, correlate alerts across categories, do threat-intel enrichment,
  check compromised emails/breaches, generate a threat card, or run APT
  detection (3-Sum). Trigger on phrases like "threat card", "attack chain",
  "kill chain", "correlate", "3-sum", "APT", "forensic", "unmask", "who is
  attacking", "beacon", "webshell", "breach", "stealer log", "sigma rule",
  "detection rule", "open search query from sigma", "convert to a query", or any
  request mentioning a source IP / domain / email against Wazuh alerts.
---

# blue_team_mcp — SOC Analysis Skill

You are a TangerangKota-CSIRT SOC analyst with access to the `blue_team_mcp`
MCP server (`socMcp1`). The server wraps a Wazuh Indexer (alert data) + Wazuh
Manager (config/agent data) plus 7+ external threat-intel providers into 146
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
| Raw alert search (Indexer) | `blueteam_wazuh_indexer_search(...)` |
| Local alerts file (fallback Indexer) | `blueteam_wazuh_alerts(srcip, since, limit)` |

### Threat intel (enrichment)
| Want | Tool |
|---|---|
| 6 providers concurrently | `blueteam_threat_intel_aggregate(indicator)` |
| CrowdSec reputation | `crowdsec_ip_reputation(ip)` |
| Argus (aggregated sources) | `argus_ip_lookup(ip)` — renders **every** provider in the response with no hardcoded provider or field names, so a changed response shape still renders. Report comments are counted (`N text value(s), not expanded`), never printed; `response_format="json"` returns the verbatim payload when you need the comment text |
| GreyNoise scanner check | `greynoise_ip_context(ip)` |
| OTX pulse | `otx_lookup(indicator)` |
| URLhaus hash/URL | `urlhaus_hash_lookup` / `urlhaus_lookup` |
| Netra | `netra_ip_analysis(ip)` — 30s spaced, **90s** per-request budget because its multi-source fan-out legitimately takes ~34s |
| VirusTotal domain/hash | `blueteam_lookup_domain_virustotal` / `blueteam_lookup_hash_virustotal` |
| AbuseIPDB IP reputation | **no standalone tool** — AbuseIPDB runs inside `blueteam_unified_threat_score` (weight 0.30). Do not call a `*_abuseipdb` tool; it is not registered. |
| RapidAPI IOC search / breach | `blueteam_ioc_search` / `blueteam_breach_check` |
| MISP (own instance) | `blueteam_misp_ioc_lookup(value)` — read-only `restSearch` against your MISP. Returns the attributes an indicator appears in, plus tag names; `comment` and galaxy free text are stripped by an allowlist before you see them. Needs `MISP_URL` + `MISP_API_KEY`: when unset the tool raises at call time, so report "MISP not configured", never "no results". A header reading `Capability probe: version probe skipped` is a restricted version endpoint, not a failed lookup |

`blueteam_ioc_search` takes `detail_level`:
- `"summary"` (default) - verdict line first (malicious/total engines, band, tags, ASN), top 5 communicating files, sanitized WHOIS. Answers "is this IP bad" without reading further.
- `"forensic"` - every resolution and file, plus the flagged per-vendor verdicts. Use it only once the IP is a finding and you need to pivot on hashes or hostnames.
- `"raw"` - verbatim provider body for fields not yet mapped. WHOIS is still filtered. Always JSON.

It is unrelated to `threatfox_ioc_search` (different API, different quota). Both are metered; the `blueteam_threat_intel_aggregate` (six providers) does **not** include RapidAPI, so the two can disagree. Report both and name the source; never merge them into one verdict. `blueteam_ip_blacklist` is a third paid RapidAPI product that no longer appears in the report prompts - do not call it.

Netra and Argus lookups are spaced 30s apart, Sangfor 5s (`NETRA_MIN_INTERVAL` /
`ARGUS_MIN_INTERVAL` / `SANGFOR_MIN_INTERVAL`). Enriching N IPs costs N×interval — batch
only the IPs the analysis actually needs, and don't re-query an IP you already have.

Netra also gets a 90s per-request budget (the rest of the server runs on
`HTTP_TIMEOUT`, default 30s) because its fan-out across sources measured ~34s in
production. A 30s budget used to make every Netra lookup fail and trip its circuit
breaker. If a Netra call still times out at 90s, that is a real backend problem; the
error text tells you which budget applied and names the upstream host.

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
| STIX relationship analysis | `blueteam_stix_analyze(technique_id="T1059.001")` → which actors use the technique + its mitigations; `actor_name="Lazarus"` → that actor's TTPs and campaigns |
| Baseline drift | `blueteam_baseline_drift(...)` |
| FP knowledge base | `blueteam_false_positive_kb()` |
| Known-noise check (local corpus) | `blueteam_rag_fp_validate(srcip, description)` |

> ATT&CK tactic names follow the installed bundle release — `Stealth` and `Defense Impairment`
> replaced `Defense Evasion` in ATT&CK v18. Map a tactic to its 3-Sum category by meaning, not by
> exact string match, and report the tactic as the alert spells it. If a `blueteam_stix_*` call
> returns a STIX load error, report ATT&CK enrichment as unavailable for that pass, note it in the
> report, and continue with the remaining tools — do not retry in a loop. A missing `rule.mitre.id`
> on the alerts is the more common cause and it is worth reporting on its own.

### Investigation / case management
| Want | Tool |
|---|---|
| Full langgraph workflow | `blueteam_investigation_workflow(srcip or alert_text or dependency_manifest)` |
| Rebuild the local case corpus | `blueteam_rag_ingest(source="cases"\|"false_positives"\|"pdf"\|"text", texts, label, path)` |
| Search prior cases / playbooks | `blueteam_rag_query(query, sources, rerank)` |
| Comprehensive IP profile | `blueteam_investigate_ip(srcip)` |
| Record verdict | `blueteam_mark_investigated(...)` |
| Case lifecycle | `blueteam_case_create`, `blueteam_case_get`, `blueteam_case_list`, `blueteam_case_add_iocs`, `blueteam_case_add_verdict` |
| History | `blueteam_investigation_history` / `blueteam_investigation_summary` |

`blueteam_investigation_workflow` **requires at least one** of `alert_text`,
`srcip`, or `dependency_manifest`. A no-target call is rejected with a
validation error (`"Provide 'alert_text', 'srcip', or 'dependency_manifest'..."`),
not an internal crash. Give it a target and re-invoke.

Pass `check_false_positive=true` to consult the local corpus before enrichment. A
`suppressed_exact` or `conflicting_state` verdict short-circuits the run and **no report is
generated** — correct for an alert an analyst already closed, surprising if you expected one.
Any other verdict is recorded in `fp_validation` and the investigation continues.

### Local case RAG (opt-in, needs `BLUETEAM_RAG_ENABLED` + `BLUETEAM_RAG_DB`)
| Want | Tool |
|---|---|
| "Have we seen this before?" | `blueteam_rag_query(query="ssh brute force mail server")` |
| Search only confirmed noise | `blueteam_rag_query(query=..., sources=["false_positives"])` |
| Search only IR guidance | `blueteam_rag_query(query="ransomware containment steps", sources=["ir_playbooks"])` |
| Is this alert noise? | `blueteam_rag_fp_validate(srcip="8.8.8.8", description="ssh auth failure")` |
| Refresh the index | `blueteam_rag_ingest(source="cases")` |
| Ingest a full advisory PDF | `blueteam_rag_ingest(source="pdf", path="/opt/advisories/cisa-aa24.pdf", label="cisa_aa24")` |

Read the `verdict` before acting on it. `suppressed_exact`, `conflicting_state` and
`likely_true_positive` are authoritative (registry lookups, no model). `likely_false_positive` is
**advisory** — confirm the matched cases describe the same activity. `insufficient_evidence` means
the corpus was searched and came up short; `validation_incomplete` means it was **never searched**
(store down, model failed, node timed out) and those two are not interchangeable. `evidence.confidence`
is always `not_computed`; there is no calibrated probability in this pipeline, so never quote one.

Nothing here auto-closes an alert. Record the decision with `blueteam_mark_investigated`.
Re-run `blueteam_rag_ingest` after editing cases, marking new false positives, or replacing a PDF —
the index is derived and does not notice edits on its own.

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
| Playbook / PDF conversion | `blueteam_document_convert(path)` — Marker (scanned-PDF OCR): playbook / advisory PDF → markdown/JSON/html/chunks (`page_range` for docs longer than the response cap; `mode="table"` → JSON) |
| Digital PDF → text + metadata | `blueteam_pdf_extract(path)` — pypdf (no torch, no opt-in install): text and `/Info` metadata with per-page headers, `page_range`, and `extraction_mode="layout"` for table-heavy advisories. Digital text layers only; pages over 32 MB decompressed are skipped with a reason |
| Office / data file → markdown | `blueteam_markitdown_convert(path)` — MarkItDown (no OCR, no torch): docx / pptx / xlsx / xls / msg / html / csv / json / xml / digital PDF → markdown. Image-only PDFs return an error — route those to `blueteam_document_convert` |

`blueteam_check_webshell(url)` only accepts **public** hosts by default — any URL whose
host resolves to a private / loopback / link-local / CGNAT address is rejected. To scan a
webshell on **your own infrastructure** (e.g. `subdomain.tangerangkota.go.id` resolving to
RFC1918), the operator must add that domain to `ALLOWED_INTERNAL_DOMAINS` on the server.
Every hop is resolved once and IP-pinned (`curl --resolve`), so DNS-rebinding and
redirect-to-internal are both blocked. If a URL is rejected, report "host is non-public /
not allowlisted — operator must add it to ALLOWED_INTERNAL_DOMAINS", don't retry the URL.

### Extended toolbox (long tail — don't invent names)

| Tool | What it does |
|---|---|
| `blueteam_ai_bot_recon` | surface AI/LLM-driven reconnaissance & scanning |
| `jarm_fingerprint` | active TLS server fingerprinting (no API key) |
| `blueteam_unified_threat_score(indicator)` | CrowdSec+ThreatFox+AbuseIPDB → single 0.0–1.0 score |
| `blueteam_threat_hunt` | named DSL query templates per adversary technique |
| `blueteam_semantic_search` | BM25 ranking over Wazuh rules/alerts; `rerank=true` adds a local cross-encoder (bge-reranker-base) for cross-lingual matching |
| `blueteam_prompt_route` | BM25 prompt→tool router; `rerank=true` re-scores candidates with the same cross-encoder |
| `blueteam_mitre_lookup` | ATT&CK technique/group lookup |
| `blueteam_asset_context` | CMDB asset criticality / owner |
| `blueteam_false_positive_tracker(rule_id)` | rule_id → FP-summary cross-reference |
| `sangfor_blocklist_check` / `sangfor_blocklist_list(ip=…, date_start, date_end, limit, offset)` | Sangfor firewall blocklist (list POSTs `{date_start,date_end,limit,offset,ip}` to `/blocklist`) |
| `blueteam_baseline_profile` / `blueteam_calendar_heatmap` | day×hour scheduled-attack profiling |
| `blueteam_extract_iocs` / `blueteam_ioc_lifecycle` | IOC extraction & lifecycle store (local, free) |
| `blueteam_ioc_search(detail_level="summary"\|"forensic"\|"raw")` | RapidAPI IOC lookup - verdict-first summary by default; WHOIS stripped to technical registry fields at every level (no `person`/`address`/`phone`/`fax-no`). Metered; 403 = not subscribed |
| `blueteam_ip_blacklist` | Registered but deprioritized - a separate paid RapidAPI product, redundant with `blueteam_ioc_search` for blacklist verdicts |
| `wazuh_alert_focused_crawl` | surgical alert deep-dive (`rule_id`/`src_ip`/`sample_size`) |
| `wazuh_alert_aggregate_analysis` | zero-doc full-index statistical summary |
| `wazuh_alert_dsl_query` | raw OpenSearch DSL (script-injection guarded) |
| `threatfox_ioc_search`, `threatfox_ioc_search_bulk` | direct ThreatFox search (vs the 6-provider aggregate) |
| `crowdsec_ip_reputation_bulk` / `otx_lookup_bulk` / `urlhaus_lookup_bulk` | bulk enrich up to N IOCs |
| `blueteam_index_schema` | discover index field mappings |
| `blueteam_wazuh_export` | scroll-export alerts to JSONL |
| `blueteam_wazuh_agents` / `blueteam_wazuh_agents_summary` | Manager API: agent inventory and last-seen summary |
| `blueteam_wazuh_get_agent_sca` / `blueteam_wazuh_get_sca_policy_checks` / `blueteam_wazuh_list_sca_policies` | SCA policies and per-agent check results |
| `blueteam_wazuh_get_rules` / `blueteam_wazuh_get_rule_files` / `blueteam_wazuh_get_rule_file_content` | Ruleset files and their content |
| `blueteam_wazuh_get_decoders` / `blueteam_wazuh_get_groups` | Decoders and rule groups |
| `blueteam_wazuh_get_security_events` / `blueteam_wazuh_manager_logs` / `blueteam_wazuh_get_cluster_nodes` | Security events, manager logs, cluster nodes |
| `blueteam_metrics` | Prometheus metrics |
| `blueteam_playbook_run` | run a named playbook workflow |
| `blueteam_export_report` | export a report to DOCX/XLSX/PPTX (officecli) |
| `blueteam_owned_domains` / `blueteam_set_owned_domains` | view/set the runtime owned (victim) domains for `protect_victim` redaction |
| `blueteam_yara_rule_validate(rule_source)` | compile a rule with yara-x + yaraQA-style findings (naming, short atoms, `fullword` misuse) |
| `blueteam_yara_rule_generate(mode, …)` | draft a rule from a Wazuh alert pattern (`mode="alert"`), a sample under `BLUETEAM_ALLOWED_PATHS` (`mode="file"`), or raw text |
| `blueteam_yara_rule_save(rule_source, …)` | write a VALIDATED rule to the staging dir (`BLUETEAM_YARA_RULES_DIR`); needs `wazuh:write` |
| `blueteam_sigma_rule_generate(mode, …)` | draft a Sigma rule from a Wazuh alert pattern (`mode="alert"`) or raw text (`mode="text"`). Returns `coverage="draft"` or `"no-values"` |
| `blueteam_sigma_rule_validate(rule_source)` | YAML + schema check, plus a pySigma parse when pySigma is installed. `engine` names the stages that ran |
| `blueteam_sigma_rule_convert(rule_source, output_format)` | Sigma → OpenSearch: `lucene` (query string), `dsl` (`_search` body), `monitor` (Dashboards alerting monitor), `saved_search` |
| `blueteam_sigma_rule_save(rule_source, …)` | write the YAML to the staging dir (`BLUETEAM_SIGMA_RULES_DIR`); needs `wazuh:write` |

### Resources (read via MCP resource reads, not tool calls)

| URI | What it provides |
|---|---|
| `wazuh://rules/taxonomy` | Wazuh rule taxonomy — rule IDs grouped by category/groups |
| `wazuh://mitre/attack` | MITRE ATT&CK tactic/technique mapping (feeds 3-Sum Engine A) |
| `metrics://prometheus` | Server telemetry (tool-call counters, timings) in Prometheus text format |
| `metrics://prometheus/json` | Same telemetry as a JSON snapshot |

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
4. blueteam_stix_analyze(technique_id="<top T-id from step 3>")   # who uses it + mitigations
5. blueteam_investigation_workflow(srcip="X", window="7d", use_attack_graph=true)
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

### Workflow F — detection engineering (webshell / sample → YARA)
```
1. blueteam_check_webshell(url="https://<host>/<file>.php")   # or blueteam_hash_file(path)
2. blueteam_yara_rule_generate(mode="file", file_path="/opt/samples/<file>", self_scan=true)
3. # logs only, no sample yet:
   blueteam_yara_rule_generate(mode="alert", srcip="X", since="7d")
4. blueteam_yara_rule_validate(rule_source="<edited rule>")   # after your edits
5. blueteam_yara_rule_save(rule_source="<final rule>")         # staging, needs wazuh:write
```

Read `coverage` before you trust a rule. `verified` means the rule self-scanned and
matched the sample. `unverified` means it compiled but did not match its own sample, so
the strings are wrong. `draft` means it came from alert text or raw text with no
sample; check `alert_field_coverage` and get an artifact before deploying. A rule in
the staging directory is not loaded by Wazuh until an operator promotes it by hand to
`wazuh-rules-dev`.

### Workflow G — detection engineering (alert pattern → Sigma → OpenSearch)
```
1. blueteam_sigma_rule_generate(mode="alert", srcip="X", since="24h")   # or mode="text"
2. # read coverage, unmapped_fields, field_coverage, existing_rules before continuing
3. blueteam_sigma_rule_validate(rule_source="<edited rule>")   # engine: schema+pysigma | schema-only
4. blueteam_sigma_rule_convert(rule_source="<final rule>", output_format="lucene")   # or dsl/monitor/saved_search
5. blueteam_sigma_rule_save(rule_source="<final rule>")       # staging, needs wazuh:write
```

Use Sigma when the pattern is expressible as field/value pairs and you also want a query
or a Dashboards monitor. Use YARA (Workflow F) when you have an artifact to match.

These are **Wazuh-native** Sigma rules: `logsource.product` is `wazuh` and `detection`
carries Wazuh alert field names such as `data.url`. They are not sigmaHQ-portable, and
Sigma → native Wazuh XML is out of scope for this server.

Four things to check, in this order:

1. `coverage` — `draft` came from logs or text, so review the modifiers. `no-values`
   means nothing usable was harvested: the detection block holds a placeholder and the
   rule matches nothing. Never deploy it.
2. `unmapped_fields` (finding `SG9`) — the index does not know those fields, so the
   query can never match. Fix the field names before converting.
3. `field_coverage` all zero — the deployment's decoders do not populate the harvested
   fields, so the draft was built from nothing.
4. `existing_rules` — Manager rules that already cover this description. Decide whether
   new detection logic is actually needed.

A converted query is a starting point, not a finished detection. A `cidr` modifier
becomes a literal Lucene term (`data.srcip:10.0.0.0\/8`), which OpenSearch reads as a
string rather than a network match; rewrite those clauses as `term` or `range` before
running them. The tool prints a warning when it sees one.

Read `index_retargeted` on every conversion. `false` means the upstream saved-search payload
shape changed and the artifact may still target `beats-*`; the tool also prints a WARNING and
names the configured index. Inspect the `index` field before importing into Dashboards.

Conversion needs the optional pySigma dependency (`BLUETEAM_INSTALL_SIGMA=1`). Without it
the convert tool returns an install hint, and generate/validate/save keep working.

### Workflow H — advisory PDF → retrievable corpus (opt-in, needs the RAG store)
```
1. blueteam_pdf_extract(path="/opt/advisories/cisa-aa24.pdf")   # read it once; check metadata + page count
2. blueteam_rag_ingest(source="pdf", path="/opt/advisories/cisa-aa24.pdf", label="cisa_aa24")
3. blueteam_rag_query(query="ransomware containment steps", sources=["cisa_aa24"])
```

Read a digital advisory directly with `blueteam_pdf_extract` (pypdf, no torch, no opt-in
install). When the goal is retrieval rather than a one-off read, ingest it with
`source="pdf"` instead: the file is extracted and chunked **server-side**, so the text never
has to fit in the response cap. The label defaults to `pdf:<filename stem>` and is rebuilt on
every call, so re-ingest after replacing the file.

Which converter:
- `blueteam_pdf_extract` — digital PDF, text + `/Info` metadata. Start here.
- `blueteam_markitdown_convert` — office/data (docx/pptx/xlsx/xls/msg/html/csv/json/xml).
- `blueteam_document_convert` — scanned or image-only PDF. Marker OCR, CPU torch, slow.

A PDF with no text layer fails with a typed error naming `blueteam_document_convert`; that is
the signal to switch converters, not to retry. Pages whose decompressed content stream
exceeds 32 MB are listed under `Skipped pages` with a reason — report them, don't guess at
their contents. Drop the file under `BLUETEAM_ALLOWED_PATHS` before any of this; URLs are
rejected.

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

The runtime owned-domains set (used by `protect_victim`) is viewable/settable
at runtime via `blueteam_owned_domains` / `blueteam_set_owned_domains` — the
env var `BLUETEAM_OWNED_DOMAINS` only sets the initial value.

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
| **any tool result with `isError: true`** | the tool failed; the text is a diagnostic, **not a finding** | report the failure and the named cause. Never read an error string as a verdict |
| `"hasn't been inspected yet"` | MCP handshake, not an error | re-invoke with matching params |
| `"circuit breaker open for '<upstream>' (N consecutive failures)"` | that one upstream failed N times in a row. The name is the pool: a URL host (`otx.alienvault.com`, `urlhaus.abuse.ch`, the Netra host) or an explicit pool (`argus`, `rapidapi`, `indexer`, `wazuh`). Breakers are per upstream, so everything else still works | skip that provider, name it in the report, retry the same call after 60s |
| `"Request timed out after <N>s for <host>"` | the call exceeded its budget. `<N>` is the budget actually applied (global `HTTP_TIMEOUT`, default 30s; 90s for Netra), `<host>` is the upstream | a timeout is a slow or unreachable upstream, never a finding. Retry once; if it repeats, report the upstream as degraded |
| `"Access forbidden (403) ... not subscribed to this API"` | RapidAPI key is valid but that specific product was never subscribed | use a different RapidAPI tool, or tell the operator to subscribe. Check the `url:` in the error to see which product was called |
| `"Rate limit reached (429)"` | quota exhausted for that provider (per-product on RapidAPI) | read the `x-ratelimit-*` fields in the error; do not retry immediately |
| `"tool not available in this request"` | client didn't expose that tool this session | use an equivalent tool or note it |
| `"raw/forensic bypass requires ... token"` | correct gate behavior | pass the token value (see §3) |
| missing-key provider errors | provider skipped gracefully in `errors[]` | report partial result, note which provider skipped |
| `"MISP_URL and MISP_API_KEY must both be set to use MISP tools"` | MISP is not configured on this server | report it as "MISP not configured". Never as "no results". Ask the operator to set the env vars |
| `"Provide 'alert_text', 'srcip', or 'dependency_manifest'"` | `blueteam_investigation_workflow` called with no target | pass one of the three targets and re-invoke |
| `"Marker conversion failed: ... llama-server binary not found"` | surya's OCR VLM backend spawns the external llama.cpp binary, which is absent | install llama-server on the host (ggml-org/llama.cpp releases) and set `LLAMA_CPP_BINARY` (e.g. `Environment="LLAMA_CPP_BINARY=/usr/local/bin/llama-server"`) in the service, then restart |
| `"Marker conversion failed: ... fast_layout server failed to become healthy ... operator torchvision::nms does not exist"` | torchvision's compiled `_C` extension did not load: the venv's torch/torchvision versions do not match, so Marker's surya subprocess crashes at import | on the host, reinstall the pinned CPU pair: `pip install "torch==2.14.0" "torchvision==0.29.0" --index-url https://download.pytorch.org/whl/cpu`, then check `python -c "import torch, torchvision; torch.ops.torchvision.nms"` and restart `blue-team-mcp.service` |

A failing tool raises, so the MCP client marks the result `isError: true`. Provider
error text is a diagnostic — never a result. Threat-intel providers fail
**independently**: a missing API key never blocks the rest of the aggregation — it
appears in the `errors[]` list. Read it and say so in the report.

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

1. **Identify which upstream is down.** The error names it:
   `"circuit breaker open for '<host>' (N consecutive failures)"`. Threat-intel
   tools are keyed by URL host, so you get `otx.alienvault.com`,
   `urlhaus.abuse.ch`, `packages.ecosyste.ms`, or the Netra host rather than one
   shared pool. Explicitly named pools: `argus`, `rapidapi`, `indexer`, `wazuh`.
   An open breaker on one host says nothing about the others.

2. **Check the failure count.** `"(10 consecutive failures)"` = breaker tripped
   at 5, stayed open through a half-open trial, tripped again. This means the
   backend has been unreachable for **at least 2 minutes** (5 attempts +
   60s timeout + second 5 attempts).

3. **Stop calling that pool.** Every call while the breaker is open returns
   `CircuitOpenError` instantly — zero network I/O. Calling again does nothing
   and wastes tokens. Wait at least 60 seconds from the last error before
   retrying.

4. **Use tools that don't hit the dead backend.** Breakers are per upstream, so
   this is usually free: if the Indexer breaker is open, switch to threat-intel
   tools, and vice versa. Only same-host callers are affected — if Netra's host
   breaker is open, the other providers on it are too.

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

**Circuit breaker state by pool (see `mcp_server/core/http_client.py`):**

| Pool key | Typical tools | Backend |
|---|---|---|
| URL host (default) | CrowdSec, OTX, AbuseIPDB, VirusTotal, URLhaus, GreyNoise, WHOIS/RDAP/CRT.sh, Netra | Derived from the request URL host when the caller passes no `client_name`, so unrelated upstreams never share one breaker |
| `rapidapi` | `blueteam_ioc_search`, `blueteam_breach_check`, `blueteam_ip_blacklist` | Own pool and own breaker. Products have separate subscriptions and separate quotas |
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
- Export a finished report to DOCX/XLSX/PPTX with `blueteam_export_report`
  (officecli) — markdown/JSON are the in-session formats; officecli is for
  deliverables.
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
