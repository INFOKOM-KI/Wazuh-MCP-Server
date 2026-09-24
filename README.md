# Blue Team MCP Server (Wazuh SIEM)

<img width="1674" height="940" alt="image" src="https://github.com/user-attachments/assets/a4a70b45-9b79-41c6-a23a-5d0e6b38931a" />


[![Wazuh-MCP-Server MCP server](https://glama.ai/mcp/servers/INFOKOM-KI/Wazuh-MCP-Server/badges/card.svg)](https://glama.ai/mcp/servers/INFOKOM-KI/Wazuh-MCP-Server)

[![Wazuh-MCP-Server MCP server](https://glama.ai/mcp/servers/INFOKOM-KI/Wazuh-MCP-Server/badges/score.svg)](https://glama.ai/mcp/servers/INFOKOM-KI/Wazuh-MCP-Server)

A defensive MCP server for Claude Desktop / any MCP client — the blue-team counterpart to
offensive tooling. **150 tools + 4 resources** (124 when `WAZUH_READ_ONLY=true`) across Wazuh SIEM, multi-provider threat
intelligence, MITRE-driven 3-Sum APT correlation, attack graphing, LangGraph investigation
workflows, local case RAG, host forensics, and opt-in HDBSCAN clustering + ATT&CK incident
labeling. Read-only by default.

**Programmer**: `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)

---

## Architecture

```
main.py -> mcp_server/  (package)
                 ├─ core/          HTTP client, redaction, audit, config, attack graph, IOC store
                 ├─ wazuh/         Indexer (OpenSearch) + Manager API (JWT auth)
                 ├─ correlation/   3-Sum engine (pure computation, MITRE-driven)
                 ├─ threat_intel/  CrowdSec, ThreatFox, OTX, URLhaus, GreyNoise + shared cache
                 ├─ agents/        LangGraph investigation + playbook workflows
                 └─ tools/         53 tool modules
```

Every tool call flows through a single pipeline in the `@blueteam_tool` decorator — the three
most-connected nodes in the code graph:

```
audit (_audit_log) -> call -> redact (_redact_alert_data) -> truncate (_truncate_if_needed)
```

All outbound HTTP flows through a per-pool circuit breaker (`http_client.CircuitBreaker`:
5 consecutive failures -> open, 60s cooldown, single half-open trial). 429 and 4xx never count
as failures, so an outage on one upstream fails fast instead of stacking retries across tools.

| Transport | Use case |
|-----------|----------|
| `stdio` | Local subprocess / SSH pipe (default) |
| `streamable_http` | Remote HTTP service (`http://<host>:<port>/mcp`) — requires `MCP_API_KEY` beyond `127.0.0.1` (bind guard enforced) |

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
# inbound auth for the HTTP transport (REQUIRED when binding beyond 127.0.0.1)
export MCP_API_KEY="btm_<43-char-base64>"        # generate: python3 -c "import secrets; print('btm_' + secrets.token_urlsafe(32))"
export MCP_API_KEY_SCOPES="wazuh:read wazuh:write"   # optional — default wazuh:read (read-only)

# run (stdio)
mcp-server-blueteam

# or remote HTTP (MCP_API_KEY is mandatory here — the server refuses to bind otherwise)
MCP_TRANSPORT=streamable_http MCP_HOST=0.0.0.0 MCP_PORT=8001 \
  MCP_API_KEY="btm_<43-char-base64>" mcp-server-blueteam
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
| Threat intel | `CROWDSEC_API_KEY`, `THREATFOX_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `NETRA_API_KEY`, `ARGUS_API_KEY`, `RAPIDAPI_KEY`, `HUDSONROCK_API_KEY` | 9 providers + RapidAPI + HudsonRock; all optional |
| RapidAPI budget | `BLUETEAM_RAPIDAPI_MONTHLY_CAP`, `BLUETEAM_RAPIDAPI_BUDGET`, `BLUETEAM_RAPIDAPI_BUDGET_HOURS`, `BLUETEAM_RAPIDAPI_CACHE`, `BLUETEAM_RAPIDAPI_RAW_WHOIS`, `BLUETEAM_RAPIDAPI_MIN_INTERVAL`, `RAPIDAPI_CACHE_TTL` | one account-wide pool (default 100/month) shared by every RapidAPI product. Budget defaults to 0, so every RapidAPI call is refused until an operator arms a window. `MIN_INTERVAL` paces requests across all of them (default 0.25s; set 7.0 where the plan requires one lookup per 7s) |
| MISP | `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFYCERT`, `MISP_CACHE_TTL`, `MISP_MIN_INTERVAL`, `MISP_MAX_CONCURRENT`, `MISP_TIMEOUT` | internal sharing instance; read-only key. `MISP_URL` without `MISP_API_KEY` fails startup. `VERIFYCERT` defaults `true` and is scoped to the MISP pool only |
| Outbound lookup spacing | `NETRA_MIN_INTERVAL`, `ARGUS_MIN_INTERVAL`, `SANGFOR_MIN_INTERVAL` | seconds between upstream lookups — default `30`/`30`/`5` |
| Outbound HTTP timeout | `HTTP_TIMEOUT` | seconds per upstream request — default `30`. Netra overrides it per request at 90s because its fan-out measured ~34s. A timeout counts as a breaker failure, so a budget below real latency trips the breaker for that upstream |
| ATT&CK STIX bundle | `MITRE_ATTACK_STIX`, `BLUETEAM_STIX_CACHE`, `BLUETEAM_STIX_MAX_AGE_DAYS`, `BLUETEAM_STIX_MAX_MB`, `BLUETEAM_STIX_RETRY_S` | `https://` URL or a local path (no `file://`/`ftp://`), cache path (default `/var/log/blue-team-mcp/mitre_enterprise_attack.json`), refresh TTL (7 days), fetch cap (100 MB — the corpus is 40 MB), retry after a failed first load (60s). A failed refresh keeps the last good bundle |
| STIX 2.1 egress | `BLUETEAM_STIX_EGRESS_ENABLED`, `BLUETEAM_STIX_IDENTITY_NAME`, `BLUETEAM_STIX_IDENTITY_SECTORS`, `BLUETEAM_STIX_IDENTITY_CONTACT`, `BLUETEAM_STIX_DEFAULT_TLP`, `BLUETEAM_STIX_NAMESPACE`, `BLUETEAM_STIX_MARKINGS_FILE` | the only egress path: `blueteam_stix_export` writes a shareable bundle. Off by default; on, it also needs `IDENTITY_NAME` and a non-empty `BLUETEAM_OWNED_DOMAINS` (fail-closed, see Security & Privacy). `DEFAULT_TLP` defaults `AMBER`. `NAMESPACE` aligns UUIDv5 ids with a peer. `MARKINGS_FILE` adds markings this repo does not ship (TLP:CLEAR, TLP:AMBER+STRICT) |
| Redaction | `BLUETEAM_REDACTION_POLICY`, `BLUETEAM_OWNED_DOMAINS`, `BLUETEAM_REDACT_*` | see Security & Privacy |
| Forensic gate | `BLUETEAM_ALLOW_FORENSIC_BYPASS`, `BLUETEAM_FORENSIC_TOKEN` | default `false` / empty |
| SSRF allowlist | `ALLOWED_INTERNAL_DOMAINS` | comma-separated internal domains `blueteam_check_webshell` may reach on non-public IPs (default: reject all non-public hosts) |
| Inbound auth | `MCP_API_KEY`, `MCP_API_KEY_SCOPES` | pre-shared API key + scopes for `streamable_http` |
| Inbound hardening | `BLUETEAM_HTTP_RATE_LIMIT`, `BLUETEAM_ALLOWED_ORIGINS` | per-IP sliding-window rate limit (req/min, `0`=off) + Origin allowlist (loopback always allowed) |
| Audit & persistence | `BLUETEAM_AUDIT_LOG`, `BLUETEAM_IOC_STORE`, `BLUETEAM_ATTACKER_REGISTRY`, `BLUETEAM_FALSE_POSITIVE_KB`, `BLUETEAM_CASE_STORE`, `BLUETEAM_CMDB_FILE` | JSONL audit trail + stores (optional) |
| Local case RAG | `BLUETEAM_RAG_ENABLED`, `BLUETEAM_RAG_DB`, `BLUETEAM_RAG_MODEL`, `BLUETEAM_RAG_CACHE_PATH`, `BLUETEAM_RAG_MAX_CANDIDATES`, `BLUETEAM_RAG_TOP_K`, `BLUETEAM_RAG_MAX_CHUNKS`, `BLUETEAM_RAG_CHUNK_CHARS`, `BLUETEAM_RAG_CHUNK_OVERLAP`, `BLUETEAM_RAG_ALLOW_DOWNLOAD`, `BLUETEAM_RAG_MODEL_SHA256` | SQLite retrieval corpus over cases / confirmed false positives / IR playbooks. `ENABLED=true` requires an absolute `DB` path or startup raises. `ALLOW_DOWNLOAD` defaults `false` (`local_files_only`). |
| Alert clustering | `BLUETEAM_CLUSTER_ENABLED`, `BLUETEAM_CLUSTER_STORE`, `BLUETEAM_CLUSTER_STORE_MAX`, `BLUETEAM_CLUSTER_TTL`, `BLUETEAM_CLUSTER_MIN_SIZE`, `BLUETEAM_CLUSTER_MIN_SAMPLES`, `BLUETEAM_CLUSTER_ASSIGN_FACTOR` | HDBSCAN over srcip entities. Off by default; needs scikit-learn (`setup.sh BLUETEAM_INSTALL_CLUSTER=1`). `ENABLED=true` requires an absolute `STORE` path or startup raises. Store is SQLite, written `0600`, and a fit written under a different feature version is refused rather than read |
| Incident labeling | `BLUETEAM_LAYA_ENABLED`, `BLUETEAM_LAYA_BACKEND`, `BLUETEAM_LAYA_MODEL_PATH`, `BLUETEAM_LAYA_MODEL_SHA256`, `BLUETEAM_LAYA_ALLOW_DOWNLOAD`, `BLUETEAM_LAYA_CONFIDENCE_FLOOR`, `BLUETEAM_LAYA_MAX_CONCURRENCY` | `BACKEND=onnx` (default) reuses the RAG embedder — no torch, no second model resident. `BACKEND=laya` requires `MODEL_PATH` **and** `MODEL_SHA256` or startup raises (fail-closed; `setup.sh` generates the pin). `FLOOR` defaults `0.6`; below it the answer is `uncertain`. `MAX_CONCURRENCY` defaults `1` |
| CPU hardening | `USE_TF`, `USE_FLAX`, `TOKENIZERS_PARALLELISM`, `HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE`, `OMP_NUM_THREADS`, `MKL_NUM_THREADS`, `OPENBLAS_NUM_THREADS`, `NUMEXPR_NUM_THREADS` | written unconditionally by `setup.sh` into `config.env` and `.env`. Thread caps bound the resident model pools (reranker, RAG embedder, Laya). `HF_HUB_OFFLINE` follows `BLUETEAM_RAG_ALLOW_DOWNLOAD` / `BLUETEAM_LAYA_ALLOW_DOWNLOAD`, so a hard offline switch cannot silently defeat them |
| Gating | `WAZUH_READ_ONLY`, `WAZUH_DISABLED_CATEGORIES`, `WAZUH_DISABLED_TOOLS` | skip destructive tools / tool categories. **The registered tool count changes with these.** `WAZUH_READ_ONLY=true` skips the `host_forensics` (23 tools) and `fail2ban` (3 tools) modules at import, so the startup line reads **124 tools registered** instead of 150: `150 - 23 - 3 = 124`. Disabling a category via `WAZUH_DISABLED_CATEGORIES` subtracts that category's tools the same way. Each skip is logged at INFO with the category name, immediately before the count line. Nothing is hardcoded: the count comes from the live FastMCP registry after import |

---

## Capabilities

### Wazuh SIEM
Alert search (`blueteam_wazuh_indexer_search`, `wazuh_alert_dsl_query`), zero-doc statistical
aggregations, schema discovery (`blueteam_index_schema`), domain/email/geo/syscheck/compliance
lookups, and Manager API tools (rules, decoders, groups, agents, security events).

### Semantic Search & Prompt Routing
`blueteam_semantic_search` (BM25 over Wazuh rule/alert corpora) and `blueteam_prompt_route`
(BM25 prompt→tool router; accepts Indonesian or English phrasing). Both can run a local
cross-encoder (`BAAI/bge-reranker-base`, ONNX, MIT) second stage over the BM25 candidates for
synonym / cross-lingual matching. The reranker is enabled by default
(`BLUETEAM_RERANK_ENABLED=true`) and pre-warmed at startup, but the per-tool default differs:
semantic search reranks, prompt routing does not. A 2026-09-21 measurement on 22 labelled prompts
(`tests/bench_rerank_routing.py`) put Indonesian top-3 routing accuracy at 7/16 with BM25 and 5/16
with the cross-encoder, at 2.97 s median / 9.67 s p95 per call; direct scoring showed the model
rates English pairs confidently (`+1.17` vs `-10.19` for a correct/incorrect tool) and Indonesian
pairs flat and negative (`-3` to `-9`, wrong winner).
Three rerankers were measured on HEAD against the same 22 labelled prompts
(`tests/bench_rerank_routing.py`):

| ranker | Indonesian top-3 | English top-3 | All top-3 | median per call |
|---|---|---|---|---|
| BM25 only (no rerank) | 10/16 | 3/6 | 13/22 | 2 ms |
| `BAAI/bge-reranker-base` | 7/16 | 0/6 | 7/22 | 4.05 s |
| `madebyaris/rerank-indonesia` | 9/16 | 0/6 | 9/22 | 0.78 s |

Routing stays BM25-only. The Indonesian-specific cross-encoder is five times faster than the
multilingual one and much closer to BM25, but still behind it, and the entire gap sits in the 12
templated report prompts: on the 10 natural Indonesian questions both rankers score 9/10. The
router's hand-written synonym map ("report" maps to aggregate plus timeline) beats any cross-encoder
on templated report requests. `blueteam_rag_query` still reranks because its corpus is a local case
store this measurement does not cover.

For a vendor-and-pin deployment set `BLUETEAM_RERANK_MODEL_PATH` to a model directory already on
disk (the `snapshot_download` layout: `config.json` plus `onnx/model.onnx` and its tokenizer files).
fastembed then reads the weights from that path and no download path is reachable, pinned or not;
combine it with `BLUETEAM_RERANK_MODEL_SHA256` so a changed file is refused before the ONNX session
is built. Cross-encoders fastembed does not ship are registered at runtime from
`CUSTOM_RERANK_MODELS` in `mcp_server/core/rerank.py`, and `madebyaris/rerank-indonesia` is already
in that table, so reproducing the row above needs only that env var plus the vendored directory.
The model name is checked against fastembed's cross-encoder registry at startup: a name it cannot
load (`BAAI/bge-reranker-v2-m3` is not in it) is a startup error, not a quiet BM25 fallback.
Runtime failures degrade to BM25-only and label themselves in `rerank_engine` / `rerank_status`.
Weights are pre-downloaded by `setup.sh`
into `BLUETEAM_RERANK_CACHE_PATH` — local-only, never a hosted API.

Truncation is rank-based with no score threshold: raw cross-encoder logits are uncalibrated across
query distributions, so a fixed floor deletes good matches. `BLUETEAM_RERANK_MAX_CANDIDATES`
(default 100) bounds the fan-out inside the shared `rerank_hits()` helper, so every caller is
bounded identically.

### Local Case RAG (`blueteam_rag_*`)
A local retrieval corpus over the SOC's own history — `case_store` records, confirmed
false-positive reasons and converted IR playbooks — plus a deterministic false-positive check.
Embeddings are computed in-process by ONNX (`fastembed.TextEmbedding`, no torch, no hosted
embedding API), stored in SQLite, and never transmitted.
- `blueteam_rag_ingest` — rebuild a corpus label. Derived labels (`cases`, `false_positives`, `pdf`) are
  rebuilt from their source of truth, so **re-run it after editing cases or marking new FPs**.
  `source="pdf"` reads a server-side PDF and chunks it page by page, so the text never passes
  through the model context and `BLUETEAM_CHARACTER_LIMIT` does not apply.
- `blueteam_rag_query` — vector recall (default 100 candidates) then the optional cross-encoder,
  returning scores plus corpus stats so a stale index is visible.
- `blueteam_rag_fp_validate` — verdict ladder over registry lookups and corpus matches:
  `suppressed_exact`, `conflicting_state`, `likely_true_positive`, `likely_false_positive`,
  `insufficient_evidence`, `validation_incomplete`. Advisory only, never writes, and
  `evidence.confidence` is always `not_computed`.

The distinction that matters: `insufficient_evidence` means the corpus **was** searched and came up
short; `validation_incomplete` means it was **never** searched. Conflating them turns a broken
store into a false-negative finding on a live alert.

### 3-Sum APT Correlation
`three_sum_correlation` runs two engines plus unified scoring:
- **Engine A** — MITRE-driven multi-IoC risk thresholding. Alerts classify by `rule.mitre.tactic`
  (via `MITRE_TACTIC_TO_CATEGORY`) and `rule.mitre.id` (resolved through the ATT&CK STIX bundle),
  scored as `rule.level × tactic weight`, and gated by a **≥2-category chained-attack rule**
  (`threshold_score` default 35).
- **Engine B** — 3-source volumetric Z-score (MAD + shoulder-check) flagging simultaneous spikes.
- Plus multi-resolution (1h/24h/7d), unified severity scoring, and Indexer degradation detection.

### Threat Intelligence
9 providers — CrowdSec, ThreatFox, OTX, URLhaus, GreyNoise, AbuseIPDB, VirusTotal, Netra, Argus —
with a unified `blueteam_threat_intel_aggregate` (concurrent fan-out) and a weighted
`blueteam_unified_threat_score`. Plus `stealer_log_check` (HudsonRock) and `jarm_fingerprint`
(TLS fingerprint for C2/malware attribution, no API key), and 3 RapidAPI lookups
(`blueteam_ip_intel_bulk`, `blueteam_ioc_search`, `blueteam_breach_check`).

**Those three share one account-wide pool** (`BLUETEAM_RAPIDAPI_MONTHLY_CAP`, default 100 requests
per month) and the guard is fail-closed: `BLUETEAM_RAPIDAPI_BUDGET` defaults to **0**, so every
call is refused with `Budget closed` until an operator arms a window for an incident
(`BLUETEAM_RAPIDAPI_BUDGET_HOURS`, default 8h, expiring on its own). The month-to-date counter and
the arm window both survive a restart, and `max_retries=0` keeps a 5xx from spending a second
request against the same pool. `blueteam_ip_intel_bulk` is the preferred path once the budget is
armed, because 20 IPs cost one request instead of 20. The scheduled report prompts advertise none
of the four and use the quota-free providers instead.

`blueteam_misp_ioc_lookup` queries your own MISP instance over `POST /attributes/restSearch`
(read-only). It is not part of `blueteam_threat_intel_aggregate`: the aggregate covers the six
public providers, MISP is operator-owned, and the two can legitimately disagree. No `pymisp`
dependency — the tool reuses `_api_call` plus the shared TTL cache and rate limiter. Community
free text (`comment`, galaxy descriptions) is stripped before the result reaches the model.

### Alert Enrichment
`blueteam_wazuh_alert_summarize`, `blueteam_beacon_detect`, `blueteam_attack_chain`,
`blueteam_threat_card`, `blueteam_wazuh_alert_compare`, `blueteam_curated_threat_report`.

### Vulnerability Management
CVE triage and remediation: NVD/EPSS/KEV/PoC enrichment (`blueteam_cve_*`), SSVC action
bands (`blueteam_cve_ssvc`), dependency-manifest scanning against OSV
(`blueteam_dependency_scan`), and vendor patch guidance (`blueteam_cve_advisory` — MSRC /
Red Hat / Ubuntu). The LangGraph workflow runs this chain in its `vuln` step and folds
vendor advisories into exported reports.

### Investigation, Graphs & Workflows
`blueteam_investigate_ip`, `blueteam_attack_graph` (networkx clusters + PageRank),
`blueteam_pivot_suggest`, `blueteam_campaign_watch`, `blueteam_stix_killchain`,
`blueteam_investigation_workflow` and `blueteam_playbook_run` (LangGraph), plus a
false-positive knowledge base (`blueteam_false_positive_kb`) that auto-suppresses known-noisy
IOCs in 3-Sum. `blueteam_investigation_workflow(..., check_false_positive=true)` inserts the local
RAG gate before enrichment; a `suppressed_exact` indicator short-circuits the run, so no report is
generated for an alert an analyst already closed.

### Host & Domain Forensics
WHOIS / CRT.sh, IOC extraction, JARM fingerprinting, typosquatting detection
(`blueteam_domain_permute`), webshell scanning, server-side JSONL export, DOCX/XLSX/PPTX report
export, and 23 host-forensics tools (log readers, fail2ban, rootkit scan, lynis, process/cron/users).

### Detection Engineering (YARA)
`blueteam_yara_rule_validate` compiles a rule with yara-x and runs yaraQA-style
checks. `blueteam_yara_rule_generate` drafts a rule from a Wazuh alert pattern
(`mode="alert"`, Indexer API), a sample under `BLUETEAM_ALLOWED_PATHS`
(`mode="file"`), or raw text. `blueteam_yara_rule_save` writes a validated rule to
the staging directory (`BLUETEAM_YARA_RULES_DIR`). Generation is read-only; saving
needs the `wazuh:write` scope. A generated rule reports `coverage`: `verified`
(self-scanned and matched its sample), `unverified` (compiled but did not match),
or `draft` (no sample, logs only). Wazuh alerts are logs, so an alert-derived rule
stays `draft` until it is tested against a real artifact.

### Detection Engineering (Sigma)
`blueteam_sigma_rule_generate` drafts a Sigma rule from a Wazuh alert pattern
(`mode="alert"`, Indexer API) or analyst text (`mode="text"`), reporting
`coverage` as `draft` or `no-values`. `blueteam_sigma_rule_validate` runs a
YAML+schema check always and a pySigma parse when pySigma is installed, naming the
stages that ran in `engine`. `blueteam_sigma_rule_convert` maps a rule to an
OpenSearch artifact through the `opensearch_lucene` backend: `lucene` (query
string), `dsl` (`_search` body), `monitor` (Dashboards alerting monitor), or
`saved_search`. `blueteam_sigma_rule_save` writes the YAML to
`BLUETEAM_SIGMA_RULES_DIR` and needs the `wazuh:write` scope.

Two Wazuh-specific notes. These are **Wazuh-native** Sigma rules,
`logsource.product: wazuh` with Wazuh alert field names in `detection`, so they are
not sigmaHQ-portable and upstream `sigma check` warns about the product. And
`blueteam_sigma_rule_generate` probes the Indexer for fields it emits, reporting
unmapped ones as finding `SG9`; a field the index does not know can never match.

Conversion needs the optional pySigma install (`BLUETEAM_INSTALL_SIGMA=1`,
see `requirements.txt`). Without it the convert tool returns an install hint and
the other three keep working. Artifacts target
`BLUETEAM_SIGMA_INDEX_PATTERN` (`wazuh-alerts-*`), never the pySigma default
`beats-*`; the response carries `index_retargeted`, and `false` means the upstream
payload shape changed and the artifact may point at the wrong index.

Sigma to native Wazuh XML rules is out of scope and needs a
written scope amendment. Promotion out of either staging directory is a manual,
reviewed step.

### Alert Clustering & Incident Labeling (opt-in)
`blueteam_alert_cluster` fits HDBSCAN over `srcip` entities and persists centroids, medoids and
per-cluster radii; `blueteam_alert_cluster_assign` places one entity into that fit.
`blueteam_incident_label` names the ATT&CK tactic an alert or text resembles and derives its
A/B/C category from the same mapping 3-Sum uses.
What makes clustering cheap: the feature vector is the aggregation the 3-Sum engine already
runs — 16 MITRE tactic level sums plus `score_a`/`score_b`/`score_c`/`total` — so there is no
embedding model, no new taxonomy and no extra Indexer work beyond the profile query. What
makes labeling cheap: the default `onnx` backend reuses the RAG embedder's ONNX session, so the
marginal cost is one embedding per call after a one-time 32-phrase anchor build.

Both tools are off by default and answer with an enable hint while their flag is down. Two
structural facts to expect:

- **Assignment is nearest-centroid, not inductive.** The pinned scikit-learn exposes
  `fit_predict` only, so a new entity is accepted when it falls inside a stored cluster's
  radius (95th percentile of member distances) and reported as `novel` otherwise.
- **A label is a resemblance, not an attribution.** `status="uncertain"` means no tactic
  reached the confidence floor — a result, not an error. The full score vector is returned so a
  human can calibrate the floor on labelled data. `scored=false` means the backend exposes no
  probabilities and the model's bare choice is reported as unscored, never with an invented
  confidence.

Deliberate non-features: no automatic refit, no background scheduler inside the server, no
member IP lists in cluster output (use `_assign` for one entity), and no stored labels.

**A campaign means one window.** `blueteam_alert_cluster` groups entities that resemble each
other *in the window you asked for*. Cluster ids are scoped to a fit, so the same campaign can
carry a different id after a refit; cross-window campaign identity is not implemented. To persist
one today, create a case for the cluster (`blueteam_case_create`) — that is a deliberate choice to
avoid a new store with its own lifecycle.

**The label vocabulary is baked, not fetched.** `mcp_server/label/mitre_tactics_generated.py` is
generated offline from the ATT&CK bundle by `python3 bake_mitre_tactics.py --bundle <path>`
(`--fetch` to download first, `--check` to report drift without writing). The runtime imports that
module: no STIX parse, no startup I/O, no network. The vocabulary is a **union** — STIX ships 15
`x-mitre-tactic` objects while this deployment scores 16 names, because the production ruleset
still emits the pre-v18 `Defense Evasion`, which v18 split into `Stealth` + `Defense Impairment`. A
bake that trusted upstream alone would drop that name and the criteria guard would raise at import.
Never edit the generated file by hand; regenerate it and let `git diff` show the vocabulary change.

#### CPU & memory envelope
Threads are capped at 2 by default (`OMP_NUM_THREADS`, inherited by MKL/OpenBLAS/NumExpr) and
`BLUETEAM_LAYA_MAX_CONCURRENCY` defaults to 1, because three model pools share the CPU: the
cross-encoder reranker (`bge-reranker-base`, ~1 GB, on by default), the RAG embedder
(`bge-small-en-v1.5`, ONNX), and — only when `BLUETEAM_LAYA_BACKEND=laya` — CPU torch plus the
Laya weights. The `onnx` labeler adds no model: it borrows the RAG embedder.

**Measured budget (owner decision, 2026-09-24).** Warm label latency p95 ≤ **300 ms** per call on
the target host, and **no new resident model above 250 MB marginal RSS** measured in a process
that has already loaded the reranker. The `onnx` backend meets both by construction: it reuses the
embedder that is already resident. The first call also builds the ONNX session and embeds 32
taxonomy phrases, so the anchors are prewarmed on a daemon thread at startup instead of being paid
by the first analyst. `BLUETEAM_LAYA_BACKEND=laya` is **unsupported by policy** — CPU torch plus
weights exceed the envelope — so the code and its tests stay as an escape hatch and are not
advertised in the report prompts; enabling it is an explicit operator exemption, not a tuning knob.

**Accuracy is unmeasured.** The floor and the softmax temperature were calibrated on a small set of
closed cases only. No top-1 or ECE figure is claimed until 200–300 labelled cases exist, and the
status is reported as "unmeasured (calibrated baseline)". Treat any accuracy number you did not
measure on this host as unmeasured.

---

## Security & Privacy

### Inbound authentication (streamable_http)

`streamable_http` is protected by a pre-shared API key in `mcp_server/core/server_auth.py`:

- `MCP_API_KEY` — format `btm_<43-char-urlsafe-base64>` (47 chars). Stored only as a SHA-256
  digest, compared with `hmac.compare_digest` (constant-time).
- `MCP_API_KEY_SCOPES` — default `wazuh:read` (read-only). Add `wazuh:write` to unlock the 13
  write tools (`blueteam_fail2ban_unban`, `blueteam_case_*`, `blueteam_set_owned_domains`,
  `blueteam_mark_investigated`, `blueteam_wazuh_export`, `blueteam_export_report`,
  `blueteam_stix_export`, `blueteam_rag_ingest`, `blueteam_capture_traffic`,
  `blueteam_yara_rule_save`, `blueteam_sigma_rule_save`). Fail-closed: no scope ⇒ read-only.
- **Bind guard** (`main.py::_start_http_transport`): a non-loopback bind without `MCP_API_KEY`
  raises `ConfigurationError` and refuses to start. Loopback stays auth-less only when no key is
  configured; when a key is set it is enforced on every request.
- **JSON depth guard** (`parse_json_body_safe`): every POST body is capped at 1 MB
  (`MAX_BODY_BYTES`) and rejected if nesting exceeds 100 levels (`MAX_JSON_DEPTH`) *before*
  `json.loads` runs — blocks the stack-exhaustion DoS from deeply nested JSON-RPC payloads.
- **Inbound rate limiter** (`SlidingWindowRateLimiter`): per-client-IP sliding-window cap
  (`BLUETEAM_HTTP_RATE_LIMIT`, requests/min, default `0` = disabled) → `429` on excess. Distinct
  from `BLUETEAM_RATE_LIMIT`, which gates destructive tools (fail2ban unban, tcpdump capture)
  with a per-minute global cap.
- **Origin validation** (`_origin_allowed`): an `Origin` header must be a loopback origin or in
  `BLUETEAM_ALLOWED_ORIGINS` (comma-separated exact origins), else `403`. Blocks browser-based
  DNS-rebinding / localhost-exfiltration. Requests without an `Origin` header (non-browser
  clients) are unaffected. The middleware is always installed — rate limiting + origin validation
  apply even on an auth-less loopback bind.

### Redaction policy

Three-state policy (`BLUETEAM_REDACTION_POLICY`, default **`protect_victim`**):

| Policy | Behavior |
|--------|----------|
| `full` | Shape-based masking of emails, private IPs, all domains, paths, user-agents — conservative fallback when `protect_victim` has no owned domains |
| `protect_victim` | Mask only victim-owned indicators (owned domains, private IPs, identities); attacker IOCs stay visible. Recommended for SOC triage. |
| `raw` | Layer-1 credential strip only — hard-gated behind `BLUETEAM_ALLOW_FORENSIC_BYPASS=true` + `BLUETEAM_FORENSIC_TOKEN` |

Layer 1 (credential stripping) applies in **all** states and is never bypassable. The
attacker-IOC registry (`core/attacker_registry.py`) exempts confirmed attacker indicators from
shape-based masking — never from Layer 1.

Two-tier unmasking on top of the policy:
- **Tier 1 — `reveal_owned=true`** — reveals only owned `*.tangerangkota.go.id` assets to the LLM,
  and unmask owned-domain bucket keys in the aggregation tools (including
  `wazuh_alert_dsl_query`). Never expands beyond `BLUETEAM_OWNED_DOMAINS`.
- **Tier 2 — `bypass_redaction=true` + `forensic_token`** — writes raw data **to disk**; the LLM
  receives only the file path, never the raw content.

Set `BLUETEAM_OWNED_DOMAINS` to your org's domains (comma-separated, e.g. `tangerangkota.go.id`).
Inspect with `blueteam_owned_domains`; update at runtime with `blueteam_set_owned_domains`
(gated by `BLUETEAM_ALLOW_RUNTIME_DOMAINS=true`, default off).

---

## SOC Analysis Prompt (copy-paste for your LLM)

A ready-to-paste prompt for a **local** LLM connected to this MCP server. Two output formats —
**Markdown** (inline) and **DOCX** (requires `officecli`, `blueteam_export_report`).

> Canonical source of truth: [`resource/skill/soc-analysis.md`](resource/skill/soc-analysis.md).
> This block is a copy of that skill's body — update the skill, not this block, when the toolset changes.

````markdown
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

**The RapidAPI budget, read this before calling any RapidAPI tool.** Every RapidAPI product draws on ONE account-wide pool of `BLUETEAM_RAPIDAPI_MONTHLY_CAP` requests (default 100/month), and the guard is fail-closed: `BLUETEAM_RAPIDAPI_BUDGET` defaults to 0, so a call is refused with `Budget closed` until an operator arms a window (`BLUETEAM_RAPIDAPI_BUDGET_HOURS`, default 8h, which expires on its own). The month-to-date counter and the arm window both survive a server restart. A refusal is not an outage and not a retry prompt: report it once, then continue with the quota-free providers.
- Prefer `blueteam_ip_intel_bulk(ips=[...])`: N IPs cost **one** request, 1-50 per call, duplicates collapsed, and the cache key ignores order so re-running the same set inside the TTL is free.
- `blueteam_ioc_search(ip)` is the single-IP path. It takes `detail_level`: `"summary"` (default) leads with the verdict line (malicious/total engines, band, tags, ASN), the top 5 communicating files and sanitized WHOIS; `"forensic"` adds every resolution and file plus the flagged per-vendor verdicts; `"raw"` returns the verbatim provider body for fields not yet mapped, with WHOIS still filtered. All three levels cost the same one request.
- `blueteam_ioc_search_bulk(ips=[...])` runs that same IOC Search product for 1-25 IPs, one metered request per IP, sequentially and spaced by `BLUETEAM_RAPIDAPI_MIN_INTERVAL`. Use it when `blueteam_ip_intel_bulk` is not subscribed, or when the plan requires paced single lookups.

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
  backend reuses the RAG embedder and costs no extra memory. The `laya` backend is
  **unsupported by policy** — CPU torch plus weights exceed the agreed 250 MB / 300 ms budget —
  so do not ask the operator to enable it. If a call reports it as the active backend, treat
  that as an operator exemption and say so in the report rather than presenting it as normal.
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
- Accuracy is **unmeasured**. No top-1, no ECE, no confidence you did not read off the
  response. Report the label, the category, the confidence and the floor, and nothing more.

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
| `rapidapi` | `blueteam_ioc_search`, `blueteam_ioc_search_bulk`, `blueteam_ip_intel_bulk`, `blueteam_breach_check` | Own pool and own breaker. All three products share ONE account-wide quota (100/month) enforced by `rapidapi_quota`, and every call is refused while the budget is closed |
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
````

---

## Requirements

- Python 3.11+
- `mcp`, `httpx[http2]`, `pydantic`, `networkx`, `langgraph`, `officecli-sdk`
- See `requirements.txt`.
- Optional, Marker PDF→markdown document conversion (`blueteam_document_convert`): `setup.sh`
  installs it only when `BLUETEAM_INSTALL_MARKER=1`. Version-pinned stack, see the marker
  block in `setup.sh` (do not float): `torch==2.14.0` + `torchvision==0.29.0` matching CPU
  pair from the pytorch CPU index, `marker-pdf==2.0.0`, `numpy<2`, `scipy<1.14`,
  `scikit-learn>=1.6.1,<2`, `pillow<11`. A floating torch/torchvision pair crashes
  Marker's surya subprocess (`operator torchvision::nms does not exist`, 300s timeout per
  conversion). `numpy<2` is required because numpy 2.x removed `np.long` (AttributeError
  inside surya/transformers); `scikit-learn<2` still resolves to a version that satisfies
  marker-pdf 2.0.0's `>=1.6.1` requirement. Scanned-page OCR needs the external `llama-server`
  binary (llama.cpp, not pip-installable): install it on the host and set `LLAMA_CPP_BINARY`
  in the service env, or OCR fails with `llama-server binary not found`. First run downloads
  the surya models (multi-GB HuggingFace download); set `BLUETEAM_PREWARM_MARKER=1` to fetch
  them at install time.
- Optional, MarkItDown office/data → markdown (`blueteam_markitdown_convert`): `setup.sh`
  installs it only when `BLUETEAM_INSTALL_MARKITDOWN=1` (no torch, no model downloads):
  `pip install "markitdown[pdf,docx,pptx,xlsx,xls,outlook]"`. Local formats only — URLs,
  `.zip`, `.epub`, audio and YouTube are held out of v1.
- pypdf PDF text + metadata (`blueteam_pdf_extract`, and `blueteam_rag_ingest(source="pdf")`):
  a plain dependency, no opt-in flag, no torch, no model download. Install plain `pypdf`,
  **never** `pypdf[image]` — the `[image]` extra pulls Pillow, which is the package that
  fights Marker's `pillow<11` pin above. Text and `/Info` metadata only.

---

## Development

- Before merge: `python3 check_guardrails.py --strict` must exit 0, and logging stays on stderr.

---
### 🤝💸💎 Sponsored by
**[Kiyararouter](https://kiyararouter.web.id)**
*Every model. One beautiful API.*

Kiyararouter is the modern OpenAI-compatible gateway for teams building with AI. Connect once, ship faster, and stay flexible.
