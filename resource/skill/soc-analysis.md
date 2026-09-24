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
Manager (config/agent data) plus 7+ external threat-intel providers into 150
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

Route the analyst's own sentence before picking from the tables below.
`blueteam_prompt_route(prompt="<the analyst's wording, Indonesian or English>", top_k=5)` ranks
every registered tool against that sentence and returns the best lexical matches, which is what
works for Indonesian phrasing without translating it first. Treat the top 5 as a shortlist and
confirm the choice against this taxonomy: the router ranks tool descriptions, it does not know your
alert context, and it only finds a tool whose description contains the vocabulary you used. When
nothing in the shortlist fits, fall back to the tables below rather than rephrasing until something
appears. Read `rerank_engine` in the response (`bm25` is the expected routing path: the
cross-encoder is off for routing, and the 2026-09-22 measurements on the 22 labelled prompts show
why. BM25 puts an acceptable tool in the top 3 for 13/22 (10/16 Indonesian) and inside the top 10
for all 22. The multilingual `bge-reranker-base` drops that to 7/22 and the Indonesian-specific
`madebyaris/rerank-indonesia` to 9/22, so the cheaper, language-matched model is both faster and
more accurate (782 ms median against 4.05 s) and still behind enriched BM25. On the 10 natural
Indonesian questions the two rankers tie at 9/10, which puts the whole gap in the 12 templated
report prompts, where the router's hand-written synonym map ("report" -> aggregate/timeline) beats
any cross-encoder. It stays on for `blueteam_rag_query`), and use `mode="buckets"` when you want to
see how it split the sentence into tokens. When the analyst's question is vague, ask them one clarifying question rather than routing a
guess.

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
| RapidAPI (one shared budget) | `blueteam_ip_intel_bulk(ips=[...])` for 1-50 IPs in **one** request; `blueteam_ioc_search(ip)` for a single IP; `blueteam_breach_check(email)`. All three draw on one account-wide pool that is **closed unless the operator armed it**, and none of them cost quota at the six-provider aggregate |
| MISP (own instance) | `blueteam_misp_ioc_lookup(value)` — read-only `restSearch` against your MISP. Returns the attributes an indicator appears in, plus tag names; `comment` and galaxy free text are stripped by an allowlist before you see them. Needs `MISP_URL` + `MISP_API_KEY`: when unset the tool raises at call time, so report "MISP not configured", never "no results". A header reading `Capability probe: version probe skipped` is a restricted version endpoint, not a failed lookup |

**The RapidAPI budget, read this before calling any of the three.** Every RapidAPI product draws on ONE account-wide pool of `BLUETEAM_RAPIDAPI_MONTHLY_CAP` requests (default 100/month), and the guard is fail-closed: `BLUETEAM_RAPIDAPI_BUDGET` defaults to 0, so a call is refused with `Budget closed` until an operator arms a window (`BLUETEAM_RAPIDAPI_BUDGET_HOURS`, default 8h, which expires on its own). The month-to-date counter and the arm window both survive a server restart. A refusal is not an outage and not a retry prompt: report it once, then continue with the quota-free providers.
- Prefer `blueteam_ip_intel_bulk(ips=[...])`: N IPs cost **one** request, 1-50 per call, duplicates collapsed, and the cache key ignores order so re-running the same set inside the TTL is free.
- `blueteam_ioc_search(ip)` is the single-IP path. It takes `detail_level`: `"summary"` (default) leads with the verdict line (malicious/total engines, band, tags, ASN), the top 5 communicating files and sanitized WHOIS; `"forensic"` adds every resolution and file plus the flagged per-vendor verdicts; `"raw"` returns the verbatim provider body for fields not yet mapped, with WHOIS still filtered. All three levels cost the same one request.

**WHOIS differs between the two IP tools, deliberately.** `blueteam_ioc_search` allowlists the technical registry fields (no `person`/`address`/`phone`/`fax-no`). `blueteam_ip_intel_bulk` returns the provider's WHOIS **verbatim** and marks the block in its output, because abuse-desk and registrant context is what escalation needs. Treat the WHOIS block from that tool as third-party data: keep it in the incident record, do not republish it, and do not carry it into a shared report. An operator can close the gap with `BLUETEAM_RAPIDAPI_RAW_WHOIS=false`, which applies the same allowlist to the bulk body.

It is unrelated to `threatfox_ioc_search` (different API, no shared budget). The `blueteam_threat_intel_aggregate` covers six providers, does **not** include RapidAPI, and costs no quota at all, which is why it is what a scheduled report uses.

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

### Alert clustering & incident labeling (opt-in)

Two opt-in subsystems. Clustering groups entities by the scores the 3-Sum engine already
computes; labeling names the ATT&CK phase a single alert resembles. Neither one asserts
that an entity is malicious.

| Want | Tool |
|---|---|
| Fit clusters over a window | `blueteam_alert_cluster(mode="fit", time_window_minutes=1440)` |
| Read the stored fit | `blueteam_alert_cluster(mode="status")` |
| Place one entity in the fit | `blueteam_alert_cluster_assign(srcip="X")` |
| Name the ATT&CK phase of an alert or text | `blueteam_incident_label(mode="alert"\|"text")` |

- `blueteam_alert_cluster` needs `BLUETEAM_CLUSTER_ENABLED=true` plus a scikit-learn
  install (`setup.sh BLUETEAM_INSTALL_CLUSTER=1`).
- `blueteam_incident_label` needs `BLUETEAM_LAYA_ENABLED=true`. The default `onnx`
  backend reuses the RAG embedder and costs no extra memory; `BLUETEAM_LAYA_BACKEND=laya`
  runs the real classifier and needs CPU torch plus vendored weights.
- While a flag is off the tool raises an enable hint. That hint is a configuration
  answer, not a failure — report it and stop, do not retry.

Reading the output:

- **A label is a resemblance, not an attribution.** It says which phase the activity
  looks like, never that the activity is confirmed. Feed it to the category, to
  `three_sum_correlation` and to `blueteam_rag_query`; never to a mitigation decision.
- `uncertain` is a result. `status="uncertain"` means no tactic reached the confidence
  floor: the honest answer for mixed or unscorable text. The full score vector is
  attached so a human can calibrate; **do not lower the floor to force a label**.
  `scored=false` means the backend exposes no probabilities — report the model's bare
  choice as unscored and never invent a confidence number for it.
- `noise` (`-1`) from a cluster fit is a result too: those entities resemble nothing in
  the window. `novelty=true` on an assignment means the entity fell outside every stored
  cluster radius, so the stored fit no longer describes the current traffic — evidence for
  an operator-run refit, never an automatic one.
- The cluster response carries **no member IP lists**, by design. Use
  `blueteam_alert_cluster_assign(srcip="X")` to ask about one entity.
- Both tools stamp a version into every response (`feature_version` for the fit,
  `criteria_version` for the label). Two results with different stamps are not comparable;
  say so instead of comparing them.

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
| Breach check (RapidAPI, budget-gated) | `blueteam_breach_check(email)` |
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
| `blueteam_semantic_search` | BM25 ranking over Wazuh rules/alerts; cross-encoder rerank (`bge-reranker-base`) is **on by default** for cross-lingual matching. Read `rerank_engine`: `bm25` means the rerank did not run and `rerank_status` says why |
| `blueteam_prompt_route` | Natural-language prompt→tool router over all registered tools; rerank **off by default** for routing (BM25 13/22 against 9/22 for the best available cross-encoder). Pass the analyst's own wording (Indonesian or English) when unsure which tool fits |
| `blueteam_mitre_lookup` | ATT&CK technique/group lookup |
| `blueteam_asset_context` | CMDB asset criticality / owner |
| `blueteam_false_positive_tracker(rule_id)` | rule_id → FP-summary cross-reference |
| `sangfor_blocklist_check` / `sangfor_blocklist_list(ip=…, date_start, date_end, limit, offset)` | Sangfor firewall blocklist (list POSTs `{date_start,date_end,limit,offset,ip}` to `/blocklist`) |
| `blueteam_baseline_profile` / `blueteam_calendar_heatmap` | day×hour scheduled-attack profiling |
| `blueteam_extract_iocs` / `blueteam_ioc_lifecycle` | IOC extraction & lifecycle store (local, free) |
| `blueteam_ip_intel_bulk(ips=[...])` | 1-50 IPs in one metered RapidAPI request, duplicates collapsed: the preferred path once the budget is armed. Private, loopback, link-local and CGNAT addresses are rejected before any request is sent |
| `blueteam_ioc_search(detail_level="summary"\|"forensic"\|"raw")` | RapidAPI single-IP lookup: verdict-first summary by default; WHOIS stripped to technical registry fields at every level (no `person`/`address`/`phone`/`fax-no`). One shared account-wide budget, so a `403` means "not subscribed" while a `Budget closed` refusal means "no window armed" |
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
| `blueteam_stix_export` | write a STIX 2.1 bundle for a peer CSIRT (identity + TLP marking + report + indicators + `indicates` relationships). Disabled unless the operator enables egress; internal values are DROPPED, never masked |
| `blueteam_owned_domains` / `blueteam_set_owned_domains` | view/set the runtime owned (victim) domains for `protect_victim` redaction |
| `blueteam_yara_rule_validate(rule_source)` | compile a rule with yara-x + yaraQA-style findings (naming, short atoms, `fullword` misuse) |
| `blueteam_yara_rule_generate(mode, …)` | draft a rule from a Wazuh alert pattern (`mode="alert"`), a sample under `BLUETEAM_ALLOWED_PATHS` (`mode="file"`), or raw text |
| `blueteam_yara_rule_save(rule_source, …)` | write a VALIDATED rule to the staging dir (`BLUETEAM_YARA_RULES_DIR`); needs `wazuh:write` |
| `blueteam_sigma_rule_generate(mode, …)` | draft a Sigma rule from a Wazuh alert pattern (`mode="alert"`) or raw text (`mode="text"`). Returns `coverage="draft"` or `"no-values"` |
| `blueteam_sigma_rule_validate(rule_source)` | YAML + schema check, plus a pySigma parse when pySigma is installed. `engine` names the stages that ran |
| `blueteam_sigma_rule_convert(rule_source, output_format)` | Sigma → OpenSearch: `lucene` (query string), `dsl` (`_search` body), `monitor` (Dashboards alerting monitor), `saved_search` |
| `blueteam_sigma_rule_save(rule_source, …)` | write the YAML to the staging dir (`BLUETEAM_SIGMA_RULES_DIR`); needs `wazuh:write` |
| `blueteam_alert_cluster(mode="fit"\|"status", time_window_minutes, min_cluster_size, min_samples)` | HDBSCAN over srcip entities built from the 3-Sum aggregation (16 tactic sums + 4 scores). Returns clusters, medoids, noise ratio; `insufficient_data` instead of an empty cluster list when the population is too small |
| `blueteam_alert_cluster_assign(srcip, fit_id, assign_factor, use_cached)` | nearest-centroid assignment against the stored fit. `label=-1` + `novelty=true` = outside every cluster radius. `pending_novelty`/`pending_refit` flag when a refit is justified |
| `blueteam_incident_label(mode="alert"\|"text", alert, text, include_probabilities, top_k)` | label one alert or text with one of the 16 ATT&CK tactics, plus the A/B/C category derived from it. `status` is `ok` / `uncertain` / `unavailable`, and `unavailable` carries the reason |

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
3. blueteam_breach_check(email="<official dinas email>")   # needs an armed budget, otherwise it refuses
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

### Workflow I — share confirmed indicators with a peer CSIRT (STIX 2.1)
```
1. blueteam_extract_iocs(text=alert_data, response_format="json")            # or the case's IOC list
2. blueteam_ioc_lifecycle(kind="ip", since_days=7, response_format="json")    # what the store already knows
3. blueteam_stix_killchain(srcip="X", since="7d")                             # technique IDs for context
4. blueteam_stix_export(indicators=[...], sources=["crowdsec","threatfox"],
                        attack_technique_ids=["T1110.001"], tlp="AMBER", confidence=70)
5. Read `dropped[...]` and the written `path`; hand the file to the operator.
```

`blueteam_stix_export` is the only egress tool in this server. It writes a STIX 2.1 bundle
(producer `identity`, TLP `marking-definition`, `report`, `indicator` objects, and optional
`indicates` relationships to ATT&CK techniques resolved from the loaded bundle) under
`BLUETEAM_EXPORT_DIR/stix/`. The file is the shareable artifact: no TAXII, no network push.
Importing it into the peer's MISP or OpenCTI is the operator's step.

Three settings decide whether it runs:

- `BLUETEAM_STIX_EGRESS_ENABLED=true` — otherwise the tool is disabled.
- `BLUETEAM_STIX_IDENTITY_NAME` — a bundle with no producer Identity is not shareable.
- `BLUETEAM_OWNED_DOMAINS` non-empty — without it, victim domains cannot be told apart from
  attacker domains, so the tool refuses instead of guessing.

What it never shares: RFC1918 / loopback / link-local / CGNAT / reserved addresses (including
IPv4-mapped IPv6 such as `::ffff:10.0.0.5`), owned domains and their subdomains, internal TLDs,
single-label hostnames (asset names), emails, non-http URLs, and URLs carrying credentials.
Excluded values are itemised in `dropped` with a reason. **A dropped value is out of the bundle,
not masked** — do not paste one back in, and never describe one as "anonymised". A second gate
re-runs the serialized bundle through the `protect_victim` pipeline; if it still changes, the
export is refused, so an internal path or hostname inside `description` blocks the write instead
of leaking. Pass `include_bundle=true` only for a small bundle you are handing straight to a MISP
API; larger bundles are written to disk and summarised, never truncated inline.

Deterministic ids (`UUIDv5` over the indicator pattern) mean re-exporting the same indicator
yields the same `indicator--` id, so the peer deduplicates instead of accumulating copies.

### Workflow J — window shape, then phase label (opt-in)
```
1. blueteam_alert_cluster(mode="fit", time_window_minutes=1440, response_format="json")
   # read entity_count, noise_ratio, and each cluster's medoid + top_tactics
2. blueteam_alert_cluster(mode="status", response_format="json")   # the stored fit + pending novelty
3. blueteam_incident_label(mode="alert", alert={...}, response_format="json")
   # label + category + confidence + floor; status ok | uncertain | unavailable
4. blueteam_alert_cluster_assign(srcip="X")     # is this entity inside a stored cluster?
5. three_sum_correlation(time_window_minutes=1440)  # the scores the cluster vector is built from
6. blueteam_rag_query(query="<label> + the alert description")   # have we closed something like this before
```

Use this when the question is "what kinds of activity are in this window" (step 1) and "what
phase does this alert look like" (step 3). Step 3 needs one alert, not a window — pass the alert
you are actually investigating, not a sample of the window.

Two orderings matter. Clustering first: the fit is over the same scores step 5 returns, so a
label read before the window shape has no context to sit in. RAG last: it answers "seen this
before", which is only a useful question once you can name what you are looking at.

If either flag is off, skip the workflow instead of substituting another tool — there is no
lexical fallback for a cluster or a label.

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
| `"[rapidapi] Budget closed: 0 requests armed"` | the account-wide budget was never armed, so the guard refused before sending anything. Expected on a scheduled report | switch to the quota-free providers (`blueteam_threat_intel_aggregate`, `crowdsec_ip_reputation`, `threatfox_ioc_search`). An operator arms `BLUETEAM_RAPIDAPI_BUDGET` and restarts for an incident window |
| `"Budget exhausted: N/100 requests used this month"` | the shared account pool is spent. A month-long block, so no retry will help | report it and stop calling RapidAPI tools until the reset date the message names |
| `"Arm window closed after 8h with N request(s) unspent"` | the incident window expired on its own, with budget still left | an operator restarts the server to arm a new window; the monthly counter is preserved |
| `"Request quota exhausted (429)"` | RapidAPI answered 429 with `x-ratelimit-requests-remaining: 0`, so the pool is gone for the billing period | terminal. Report it and do not retry |
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
- Don't call `blueteam_breach_check` repeatedly when the breaker is open:
  each call fails instantly with the same error. A `Budget closed` refusal
  behaves the same way and will not clear on its own, so report it and stop.
- Don't restart the server hoping to clear the breaker — breakers are
  in-memory per pool. Restarting an MCP server mid-session is worse than
  waiting (it breaks the JSON-RPC channel).
- Don't report "all tools broken" — name the specific pool and what tools
  still work.

**Circuit breaker state by pool (see `mcp_server/core/http_client.py`):**

| Pool key | Typical tools | Backend |
|---|---|---|
| URL host (default) | CrowdSec, OTX, AbuseIPDB, VirusTotal, URLhaus, GreyNoise, WHOIS/RDAP/CRT.sh, Netra | Derived from the request URL host when the caller passes no `client_name`, so unrelated upstreams never share one breaker |
| `rapidapi` | `blueteam_ioc_search`, `blueteam_ip_intel_bulk`, `blueteam_breach_check` | Own pool and own breaker. All three products share ONE account-wide quota (100/month) enforced by `rapidapi_quota`, and every call is refused while the budget is closed |
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
7. STIX sharing is egress, not enrichment. `blueteam_stix_export` stays off unless
   the operator enabled it; a value listed in `dropped` is out of the bundle, so
   never re-add one and never call the result "anonymised". You cannot send a
   bundle — produce it, report `path`, `sha256`, `tlp`, and let the operator
transport it.
8. A label is never a verdict. `blueteam_incident_label` says what an alert
   resembles; `status="uncertain"` and `scored=false` mean "not enough signal",
   and neither is a reason to relax the floor or to promote an entity to malicious.
9. Only call the cluster/label tools when their flag is on. An enable hint from
   `blueteam_alert_cluster` or `blueteam_incident_label` names the exact env var
   and the setup.sh flag; report both and move on.
