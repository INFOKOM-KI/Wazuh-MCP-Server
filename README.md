# Blue Team MCP Server (Wazuh SIEM)

A defensive security MCP server for Claude Desktop or any MCP Client - the defender's counterpart to [mcp-kali-server](https://www.kali.org/blog/kali-llm-claude-desktop/).

Where Kali Linux gives Claude offensive tools (nmap, gobuster, sqlmap), this gives Claude **blue team / SOC analyst tools** to investigate, monitor, and harden your systems.

**Programmer** : `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)
**Recoded** :  `https://github.com/not2cleverdotme/blue-team-mcp`

---

## Architecture

`main.py` (with the `mcp_server/` package) is a **modular MCP server** with 97 tools spanning host forensics, Wazuh SIEM, threat intelligence, Sangfor blocklist integration, alert enrichment, 3-Sum APT correlation engine, MITRE ATT&CK, threat hunting, domain investigation, and IOC extraction. It supports two transports:

| Transport | Use case | MCP client connection |
|---|---|---|
| `stdio` | Local subprocess or SSH pipe | Direct (Claude Desktop stdio) |
| `streamable_http` | Remote HTTP service | `http://<host>:<port>/mcp` |

```
                          ┌──────────────────────────────────┐
                          │     main.py                     │
                          │     97 tools · modular · 4 resources  │
                          │                                  │
                          │  ┌────────────────────────────┐  │
                          │  │ Host Forensics (26 tools)  │  │
                          │  │ • Log analysis             │  │
                          │  │ • Network monitoring       │  │
                          │  │ • Fail2Ban management      │  │
                          │  │ • File integrity           │  │
                          │  │ • System hardening (Lynis) │  │
                          │  │ • User/session monitoring  │  │
                          │  │ • Process & cron analysis  │  │
                          │  │ • System health            │  │
                          │  └────────────────────────────┘  │
                          │  ┌────────────────────────────┐  │
                          │  │ Wazuh SIEM (14 tools)     │  │
                          │  │ • Agent inventory & status │  │
                          │  │ • Security alerts          │  │
                          │  │ • Manager logs             │  │
                          │  │ • OpenSearch indexer query │  │
                          │  │ • Email/domain compromise  │  │
                          │  │ • Alert timeline           │  │
                          │  │ • Attack velocity          │  │
                          │  │ • 3-Sum APT correlation    │  │
                          │  └────────────────────────────┘  │
                          │  ┌────────────────────────────┐  │
                          │  │ Threat Intel (8 tools)     │  │
                          │  │ • AbuseIPDB IP reputation  │  │
                          │  │ • VirusTotal hash & domain │  │
                          │  │ • CrowdSec CTI (2 tools)   │  │
                          │  │ • GreyNoise Community      │
                          │  │ • Netra multi-source        │  │
                          │  └────────────────────────────┘  │
                          └──────────────────────────────────┘
                            │              │
                       stdio      streamable_http
                      (default)      :8000/mcp
```

### Two deployment modes

**Mode 1 — Local via SSH (stdio):** Claude Desktop connects over SSH; the server runs as a subprocess on the defender host.

```
┌─────────────────────┐        SSH + stdio     ┌─────────────────────────┐
│   Your Workstation  │ ────────────────────── │    Defender Host        │
│   Claude Desktop    │                        │   Ubuntu/Debian Server  │
└─────────────────────┘                        │   main.py               │
                                               └─────────────────────────┘
```

**Mode 2 — Remote service (Streamable HTTP):** The server runs as a persistent HTTP service. Any MCP client connects over the network — no SSH required.

```
┌─────────────────────┐     Streamable HTTP     ┌─────────────────────────┐
│   Any MCP Client    │ ────────────────────── │    Defender Host        │
│   (Claude Desktop,  │     http://<host>:8000    │   systemd service:      │
│    custom client)   │                        │   main.py               │
└─────────────────────┘                        │   --transport http      │
                                               └─────────────────────────┘
```

| File | Tools | When to use |
|---|---|---|
| `main.py` + `mcp_server/` | **All 97 tools** | **Recommended** — full capabilities, credential stripping, PII redaction |

---

## Performance Architecture

The suite has been refactored for **bulk data processing and concurrent workloads** beyond single-analyst interactive triage. Every server in the suite now shares the same performance patterns.

### Wazuh Server (`main.py` + `mcp_server/`)

#### Cursor-Based Pagination (Bulk Data Without Hard Caps)

All Wazuh tools support iterative cursor pagination via base64-encoded JSON tokens. Each page returns a `next_cursor`; pass it back as the `cursor` parameter to fetch the next page. `next_cursor` is `null` when the dataset is exhausted.

| Tool | Pagination Mechanism | Max per Page | Cursor Shape |
|---|---|---|---|
| `wazuh_alert_aggregate_analysis` | OpenSearch `size:0` aggregations (server-side) — covers ALL matching docs, **no document limit** | ∞ (covers all matching docs) | n/a — no cursor needed |
| `wazuh_alert_dsl_query` | OpenSearch `size:0` aggregations (user-supplied DSL) — covers ALL matching docs | ∞ (covers all matching docs) | n/a — no cursor needed |
| `wazuh_alert_focused_crawl` | OpenSearch `search_after` (sort-key traversal) | 200 | `{"search_after": [<sort_values>]}` |
| `blueteam_wazuh_indexer_search` | OpenSearch `search_after` (sort-key traversal) — also supports **auto-pagination** (aggregate or forensic via `max_scanned`) | 10,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_wazuh_indexer_search` | Alias for `blueteam_wazuh_indexer_search` — identical behaviour | 10,000 | `{"search_after": [<sort_values>]}` |
| `blueteam_wazuh_agents` | Wazuh API `offset`/`limit` | 10,000 | `{"offset": N}` |
| `blueteam_wazuh_manager_logs` | Wazuh API `offset`/`limit` | **500** (auto capped) | `{"offset": N}` |
| `blueteam_wazuh_alerts` | Line-offset in local `alerts.json` | 2,000 | `{"scanned": N}` |
| `wazuh_email_lookup` | OpenSearch `search_after` (sort-key traversal) | 1,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_domain_lookup` | OpenSearch `search_after` (sort-key traversal) — also supports **auto-pagination** via `max_scanned` | 10,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_compromised_emails_analysis` | OpenSearch `search_after` (sort-key traversal) — auto-paginates internally per batch | 1,000 | `{"search_after": [<sort_values>]}` |
| `wazuh_alert_timeline` | OpenSearch `date_histogram` (size:0, server-side) | ∞ (covers all matching docs) | n/a — no cursor needed |
| `wazuh_attack_velocity` | OpenSearch `date_histogram` (size:0, server-side) | ∞ (covers all matching docs) | n/a — no cursor needed |

**Agent workflow:**
```
1. Call tool (no cursor) → page 1 + next_cursor
2. Call tool(cursor=next_cursor) → page 2 + next_cursor
3. Repeat until next_cursor is null — all results retrieved
```

All input schemas are **backward-compatible** — `cursor` is optional and defaults are unchanged.

#### Relative Time Expressions

All Wazuh tools accept **relative time expressions** for `since`/`until` parameters in addition to ISO 8601 strings:

| Expression | Meaning | Example |
|---|---|---|
| `Ns` | N seconds ago | `15s` — last 15 seconds |
| `Nm` | N minutes ago | `5m` / `30m` — last 5 / 30 minutes |
| `Nh` | N hours ago | `1h` / `24h` / `6h` — last N hours |
| `Nd` | N days ago | `1d` / `7d` / `30d` — last N days |
| `Nw` | N weeks ago | `1w` / `4w` — last N weeks |
| ISO 8601 | Absolute timestamp (pass-through) | `2026-07-07T17:00:00Z` |

Supported by: `blueteam_wazuh_alerts`, `blueteam_wazuh_indexer_search`, `wazuh_email_lookup`, `wazuh_domain_lookup`, `wazuh_compromised_emails_analysis`, `wazuh_alert_timeline`, `wazuh_attack_velocity`.

#### Paging via `search_after` (`blueteam_wazuh_indexer_search`)

The Wazuh Indexer search tool was migrated from offset-based pagination (`from`/`size`) to OpenSearch's `search_after` cursor, eliminating the 10,000-document `max_result_window` ceiling:

- **Sort anchor**: Results are ordered by `@timestamp` (ascending) with `_id` as a deterministic tie-breaker. This guarantees every document has a unique, stable sort key.
- **Cursor traversal**: `next_cursor` encodes the raw sort values of the last document in the current page. On the next call, those values are sent as the `search_after` array — OpenSearch resumes the scan from exactly where the previous page ended.
- **Truncation metadata**: The response exposes `total` as an object `{"value": <int>, "relation": <"eq"|"gte">}`. When `relation` is `"gte"` (greater-than-or-equal), the LLM client knows the true document count exceeds the reported ceiling and continues paginating.
- **Natural exhaustion**: `next_cursor` becomes `null` when the number of returned documents is strictly less than the requested `limit` — no arithmetic against a capped `total.value`.

#### Auto Cap Limit Guard (Self Healing Defense)

The Wazuh Manager API (`/manager/logs`) rejects `limit > 500` with HTTP 400. The Pydantic input model allows up to 1,000, creating a gap where LLM clients can inadvertently construct failing requests. The `blueteam_wazuh_manager_logs` tool now applies an inline safety clamp before the HTTP call:

```python
wazuh_safe_limit = min(params.limit, 500)
```

This silently caps the value to 500 at the application layer. The client still receives the full pagination metadata (`next_cursor`, `total`) and can iterate through all results without ever triggering a validation error.

In addition, the global `_handle_api_error` helper returns a specific, actionable message for HTTP 400 (Bad Request) advising the caller to reduce limit size or switch filter parameters. This guard is deployed across all three server files.

#### Remote Architecture Fallback (`blueteam_wazuh_alerts`)

When the Wazuh Manager runs on a remote host, the local `alerts.json` file is absent. Instead of a generic OS error, the tool returns a strict metadata instruction:

```
[CRITICAL METADATA] This tool is disabled because the Wazuh Manager
is running on a remote host. DO NOT RETRY this local tool. You MUST
immediately switch to 'blueteam_wazuh_indexer_search' or
'blueteam_wazuh_manager_logs' to query security events.
```

This prevents the LLM client from wasting context loops retrying a fundamentally unavailable data path and directs it toward the correct remote-capable alternatives.

#### Shared HTTP Client with Connection Pooling

Four dedicated `httpx.AsyncClient` instances, one per SSL trust domain:

| Client | `verify` | Endpoints |
|---|---|---|
| `_get_http_client()` | `True` (public CA) | AbuseIPDB, VirusTotal, CrowdSec CTI, GreyNoise |
| `_get_netra_http_client()` | `NETRA_VERIFY_SSL` (default `false`) | Netra Threat Intelligence (<your_CTI>:8013) |
| `_get_wazuh_client()` | `WAZUH_API_VERIFY_SSL` (default `true`) | Wazuh Manager API (port 55000) |
| `_get_indexer_client()` | `WAZUH_INDEXER_VERIFY_SSL` (default `true`) | OpenSearch (port 9200) |

Each client pools connections independently (20 keepalive / 100 max for public APIs; 5 / 20 for Netra staging; 10 / 50 for Wazuh and Indexer). SSL verification is set at client creation — no per-request `verify=` keyword arguments.

#### Wazuh JWT Token Caching

Cached for **300 seconds (5 minutes)** with automatic cache clearance on authentication failure.

#### Non-Blocking Subprocess Execution

`_run_async()` wraps synchronous subprocess calls in `asyncio.to_thread()`, preventing 30 tools from blocking the event loop under concurrent load.

### CrowdSec CTI — In-Memory TTL Cache + Bulk Lookups

CrowdSec IP reputation and GreyNoise context lookups are integrated directly into the unified server (`main.py` + `mcp_server/` package). All functionality is available through the main server — no standalone files needed.

#### In-Memory Cache (CrowdSec CTI Only)

CrowdSec CTI responses are cached in-process with configurable TTL:

- **Default TTL**: 900 seconds (15 minutes) — configurable via `CROWDSEC_CACHE_TTL`
- **Cache scope**: per-IP, per-path — identical requests hit the cache; different IPs do not
- **Error exclusion**: HTTP 4xx/5xx responses are NEVER cached (structurally excluded — `raise_for_status()` throws before the cache-store point)
- **Cache hit**: returns stored data immediately with no HTTP call
- **Cache expired**: stale entry is deleted, fresh HTTP call is made, result is re-cached

#### Parallel Bulk IP Lookups (CrowdSec Only)

`crowdsec_ip_reputation_bulk` executes up to 10 IP lookups concurrently via `asyncio.gather()` bounded by an `asyncio.Semaphore`:

- **Default concurrency**: 5 (configurable via `BLUETEAM_BULK_CONCURRENCY`)
- **Error isolation**: per-IP failure does not affect sibling lookups
- **Latency**: ~5× speedup vs serial iteration

### External API Resilience

All external API calls (CrowdSec CTI, Wazuh Manager, Wazuh Indexer, Argus) use a simple try/except pattern with specific exception handling — no circuit breaker state machine needed for a local MCP server.

```python
try:
    data = await _do_request()
except httpx.HTTPStatusError as e:
    return {"error": f"API error: {e.response.status_code}"}
except httpx.TimeoutException:
    return {"error": "Request timed out"}
```

**Per-service caching** (CrowdSec CTI only): successful responses are cached in-memory with a configurable TTL (`CROWDSEC_CACHE_TTL`, default 900s). Cache hits skip the HTTP call entirely — no exception handling needed. Error responses are never cached.

### Credential & Secret Stripping (Output Sanitization)

Ported from the Wazuh-MCP-Server output sanitization pattern. Before any Wazuh alert or traffic capture data reaches the LLM context, `_redact_alert_data()` strips credentials, API keys, and secret material from `full_log` and other text fields.

**Applied automatically** to ALL tool outputs that may contain sensitive data — Wazuh alerts, log readers, user lists, SSH keys, cron jobs, process lists, system health, and network captures. Six-layer pipeline with per-layer env var control:

- Layer 1 (MANDATORY): Credential stripping (15 regex patterns, never bypassable)
- Layer 2: Email redaction (`BLUETEAM_REDACT_EMAILS`, default `true`)
- Layer 3: Internal IP masking (`BLUETEAM_REDACT_PII`, default `true`)
- Layer 4: Domain/hostname masking (`BLUETEAM_REDACT_DOMAINS`, default `true`)
- Layer 5: Log location masking (`BLUETEAM_REDACT_LOCATIONS`, default `true`)
- Layer 6: User-agent truncation (`BLUETEAM_REDACT_UAS`, default `true`)

Per-call override: `bypass_redaction=True` skips all optional Layers 2-6.

**Stripping rules (15 credential regex patterns + 4 PII/mask layers, applied in order):**

| Category | Patterns detected | Replacement |
|----------|------------------|-------------|
| Auth headers | `Authorization: Bearer <token>`, `Authorization: Basic <creds>` | `<BEARER_REDACTED>`, `<BASIC_REDACTED>` |
| API keys | `x-api-key: <key>`, `api_key=<value>` | `<API_KEY_REDACTED>` |
| JWT tokens | 3-segment base64url tokens starting with `eyJ` | `<JWT_REDACTED>` |
| Private keys | PEM blocks (`-----BEGIN ... PRIVATE KEY-----`) | `<PRIVATE_KEY_REDACTED>` |
| Cloud keys | AWS (`AKIA...`), Google (`AIza...`) | `<AWS_ACCESS_KEY_REDACTED>`, `<GOOGLE_API_KEY_REDACTED>` |
| Payment keys | Stripe (`sk_live_...`, `sk_test_...`) | `<STRIPE_KEY_REDACTED>` |
| VCS tokens | GitHub (`ghp_...`, `gho_...`, etc.), GitLab (`glpat-...`) | `<GITHUB_TOKEN_REDACTED>`, `<GITLAB_TOKEN_REDACTED>` |
| AI API keys | Anthropic (`sk-ant-...`), OpenAI (`sk-proj-...`) | `<AI_API_KEY_REDACTED>` |
| Messaging | Slack (`xoxb-...`, `xoxp-...`, etc.) | `<SLACK_TOKEN_REDACTED>` |
| Passwords | `password=`, `passwd=`, `pwd=`, `secret=` params | `password=<PASSWORD_REDACTED>` |
| **Layer 4 — Domains** | `data.domain`, standalone hostnames in `full_log` | Subdomain masked (`e-***i.tangerangkota.go.id`), parent+TLD visible |
| **Layer 5 — Locations** | `location` field (file paths) | `.../access_log [h:a3f8c2]` (leaf + forensic hash) |
| **Layer 6 — User agents** | `data.user_agent`, UA strings in `full_log` | Truncated to 80 chars (OS/browser preserved) |

The credential stripping (Layer 1) runs **before** all other masking inside `_redact_alert_data()`. All six layers are independently controlled by their `BLUETEAM_REDACT_*` env var. The original alert data on disk is never modified.

### GreyNoise Community — Free, No API Key

GreyNoise context lookups (`greynoise_ip_context`) are integrated into the unified server and require no authentication. The Community API classifies IPs as internet scanners (noise), business services (RIOT), or both — with interpretation guidance in the markdown output.

---

## Configuration Reference

All environment variables accepted by the suite. Variables marked **[unified]** apply to all three servers; others are server-specific.

### Performance & Limits [unified]

| Variable | Default | Description |
|---|---|---|
| `BLUETEAM_CHARACTER_LIMIT` | `100000` | Maximum characters per tool response before truncation |
| `WAZUH_INDEXER_MAX_SIZE` | `10000` | Max documents per page in Wazuh Indexer search queries |
| `BLUETEAM_ALLOW_UNTRUNCATED` | `false` | ADMIN GATE — enables `bypass_character_limit` and `include_all_docs` for forensic deep-dives |

### CrowdSec CTI Cache

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_CACHE_TTL` | `900` | In-memory cache TTL in seconds for CrowdSec CTI responses |

### Wazuh API

| Variable | Default | Description |
|---|---|---|
| `WAZUH_API_URL` | (empty) | Wazuh Manager API base URL (`https://<host>:55000`) |
| `WAZUH_API_USER` | `wazuh-wui` | Wazuh API username |
| `WAZUH_API_PASSWORD` | (empty) | Wazuh API password |
| `WAZUH_API_VERIFY_SSL` | `true` | TLS certificate verification for Wazuh API |

### Wazuh Indexer (OpenSearch)

| Variable | Default | Description |
|---|---|---|
| `WAZUH_INDEXER_URL` | (empty) | OpenSearch base URL (`https://<host>:9200`) |
| `WAZUH_INDEXER_USER` | `admin` | OpenSearch username |
| `WAZUH_INDEXER_PASSWORD` | (empty) | OpenSearch password |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | TLS certificate verification for indexer |
| `WAZUH_INDEXER_MAX_SIZE` | `10000` | Max documents per page in `_wazuh_indexer_search` |

### Threat Intelligence APIs

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_API_KEY` | (empty) | CrowdSec CTI API key (required for CrowdSec tools) |
| `ABUSEIPDB_API_KEY` | (empty) | AbuseIPDB API key |
| `VIRUSTOTAL_API_KEY` | (empty) | VirusTotal API key |
| `NETRA_API_KEY` | (empty) | Netra Threat Intelligence API key (Contact us : TangerangKota-CSIRT) |
| `ARGUS_API_KEY` | (empty) | Argus Threat Intelligence API key (Contact us : TangerangKota-CSIRT) |
| `ARGUS_BASE_URL` | (empty) | Argus Threat Intelligence API base URL (Contact us : TangerangKota-CSIRT) |
| `NETRA_VERIFY_SSL` | `false` | TLS certificate verification for Netra API (set `true` for production) |

### Transport & Deployment

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `streamable_http` |
| `MCP_HOST` | `127.0.0.1` | Bind address for Streamable HTTP transport |
| `MCP_PORT` | `8000` | Bind port for Streamable HTTP transport |
| `BLUE_TEAM_MCP_SERVER_NAME` | `blue_team_mcp` | Server name reported to MCP clients — use lowercase to avoid LLM casing mismatches |
| `LOG_LEVEL` | `INFO` | Python logging level |

### Security & Auditing

| Variable | Default | Description |
|---|---|---|
| `BLUETEAM_AUDIT_LOG` | (empty) | Path to audit log file |
| `BLUETEAM_INVESTIGATION_HISTORY` | (empty) | Path to investigation history JSONL file |
| `BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES` | `10000` | Max entries before tail-truncation |
| `BLUETEAM_RATE_LIMIT` | `0` (disabled) | Max tool calls per minute |
| `BLUETEAM_ALLOWED_PATHS` | `/var:/etc:/home:/opt:/usr` | Colon-separated path allowlist for file tools |
| `BLUETEAM_CAPTURE_DIR` | `/tmp` | Output directory for `blueteam_capture_traffic` pcap files |
| `BLUETEAM_REDACT_PII` | `true` | Mask internal IPs (RFC1918, loopback, IPv6 ::1) |
| `BLUETEAM_REDACT_EMAILS` | `true` | Hash email local-parts in alert payloads (domain preserved) |
| `BLUETEAM_REDACT_DOMAINS` | `true` | Mask subdomains in `data.domain` and `full_log` |
| `BLUETEAM_REDACT_LOCATIONS` | `true` | Strip directory tree from `location` field |
| `BLUETEAM_REDACT_UAS` | `true` | Truncate `data.user_agent` to 80 chars |
| `BLUETEAM_REDACT_SALT` | (hostname-derived) | Salt for deterministic forensic email/ path hashing |
| `BLUETEAM_REDACTION_POLICY` | `full` | Redaction policy: `full` (shape-based) / `protect_victim` (victim-owned only) |
| `BLUETEAM_OWNED_DOMAINS` | *(empty)* | Comma-separated owned domains — victim masking under `protect_victim` |
| `BLUETEAM_ALLOW_FORENSIC_BYPASS` | `false` | Allow `bypass_redaction` / `redaction_policy='raw'` (Layer 1 still applied) |
| `BLUETEAM_FORENSIC_TOKEN` | *(empty)* | Operator token required for raw/bypass when set |
| `BLUETEAM_ATTACKER_REGISTRY` | *(empty)* | JSONL path for attacker-IOC registry persistence |
| `BLUETEAM_ATTACKER_REGISTRY_TTL` | `604800` | Registry entry TTL in seconds (0 = never expire) |
| `BLUETEAM_ATTACKER_REGISTRY_MAX` | `10000` | Registry entry cap (oldest evicted) |
| `BLUETEAM_IOC_STORE` | *(empty)* | JSONL path for the IOC lifecycle store |
| `BLUETEAM_IOC_STORE_MAX` | `50000` | IOC store cap |
| `BLUETEAM_IOC_STORE_TTL` | `7776000` | Seconds before dead IOC entries are pruned (90 days) |
| `BLUETEAM_LANGGRAPH_DB` | *(empty)* | SQLite path for LangGraph persistence — survives restarts |
| `BLUETEAM_LANGGRAPH_NODE_TIMEOUT` | `120` | Per-node timeout seconds for investigation/playbook workflows |
| `BLUETEAM_AUTO_PROMOTE_IPS` | `false` | Auto-promote consistently-observed IPs to the registry |
| `BLUETEAM_EXPORT_RETENTION_DAYS` | `0` | Prune `export_*.jsonl` older than N days (0 = keep forever) |
| `BLUETEAM_CAMPAIGN_SNAPSHOTS` | *(empty)* | JSONL path for campaign-watch component snapshots |
| `BLUETEAM_STIX_CACHE` | `/var/log/blue-team-mcp/...` | Local cache path for the MITRE ATT&CK STIX bundle |

---

## Quick Start

### 1. On your Defender Host (Ubuntu/Debian)

```bash
git clone https://github.com/INFOKOM-KI/blue-team-soc-mcp.git
cd blue-team-mcp
sudo bash setup.sh
```

The setup script will:
- Install system packages (tcpdump, fail2ban, lynis, rkhunter, chkrootkit, and Python 3 toolchain)
- Create a Python virtualenv with MCP dependencies at `/opt/blue-team-mcp/venv`
- Copy all server files, `requirements.txt`, and `README.md` to `/opt/blue-team-mcp/`
- Place the `mcp-server-blueteam` wrapper in `/usr/local/bin`
- Grant tcpdump network capture capabilities

### 2. Set API Keys and Wazuh (optional but recommended)

Edit the config file created by setup:

```bash
sudo nano /opt/blue-team-mcp/config.env
```

Uncomment and set the variables you need:

- **CROWDSEC_API_KEY** — https://www.crowdsec.net/en/user/profile (free CTI tier; powers the `crowdsec_ip_reputation` tools)
- **ABUSEIPDB_API_KEY** — https://www.abuseipdb.com/account/api
- **VIRUSTOTAL_API_KEY** — https://www.virustotal.com/gui/my-apikey
- **WAZUH_API_URL** — `https://<host>:55000` (if Wazuh is on same host) or `https://<host>:55000`
- **WAZUH_API_USER** — `wazuh-wui` (Wazuh Docker default)
- **WAZUH_API_PASSWORD** — e.g. `MyS3cr37P450r.*-` (Wazuh Docker default)
- **WAZUH_API_VERIFY_SSL** — `false` for self-signed certs
- **WAZUH_INDEXER_URL** — `https://<host>:9200` (if on same host) or `https://<host>:9200`
- **WAZUH_INDEXER_USER** — `admin` (indexer default)
- **WAZUH_INDEXER_PASSWORD** — indexer password (often different from Wazuh API)
- **WAZUH_INDEXER_VERIFY_SSL** — `false` for self-signed certs

**GreyNoise Community requires no API key** — the `greynoise_ip_context` tool works out of the box (rate-limited per GreyNoise's fair-use policy).

**Note:** The indexer (port 9200) stores HYDRA-DC Windows events in OpenSearch. Its password may differ from the Wazuh API. For Wazuh Docker, check your `docker-compose` or `.env` for `OPENSEARCH_INITIAL_ADMIN_PASSWORD`. If adding Indexer support to an existing install, re-run `setup.sh` to update the wrapper with the new exports.

### 3. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).

**Option A — Local deployment (SSH + stdio):**

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "command": "ssh",
      "args": [
        "-i", "/Users/defence/.ssh/ubuntu-soc",
        "soc-admin@192.168.153.5",
        "mcp-server-blueteam"
      ],
      "transport": "stdio"
    }
  }
}
```

**Option B — Remote service (Streamable HTTP, recommended for shared SOC use):**

First start the server on the defender host:
```bash
python3 main.py --transport streamable_http --host 0.0.0.0 --port 8000
```

Then point Claude Desktop at it:
```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "url": "http://192.168.153.5:8000/mcp",
      "transport": "streamable-http"
    }
  }
}
```

Replace `192.168.153.5` with the IP reachable from your workstation (`192.168.153.5` for NAT, `172.16.101.5` for LAB).

Restart Claude Desktop. You should see all 97 blue-team-mcp tools available.

### 4. Production Deployment

#### 4.1 Systemd Service

Create a persistent systemd service for automatic startup and crash recovery:

```bash
sudo nano /etc/systemd/system/blue-team-mcp.service
```

```ini
[Unit]
Description=Blue Team MCP Server (Wazuh SIEM)
Documentation=https://github.com/INFOKOM-KI/blue-team-soc-mcp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blueteam-mcp
Group=blueteam-mcp
WorkingDirectory=/opt/blue-team-mcp
EnvironmentFile=/opt/blue-team-mcp/config.env
Environment="MCP_TRANSPORT=streamable_http"
Environment="MCP_HOST=127.0.0.1"
Environment="MCP_PORT=8000"
ExecStart=/usr/local/bin/mcp-server-blueteam
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/blue-team-mcp
ReadOnlyPaths=/var/log /etc

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blue-team-mcp

[Install]
WantedBy=multi-user.target
```

```bash
# Create dedicated service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin blueteam-mcp

# Create log directory
sudo mkdir -p /var/log/blue-team-mcp
sudo chown blueteam-mcp:blueteam-mcp /var/log/blue-team-mcp

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable blue-team-mcp
sudo systemctl start blue-team-mcp
sudo systemctl status blue-team-mcp
```

#### 4.2 Log Rotation

Prevent unbounded disk growth from audit logs and investigation history:

```bash
sudo nano /etc/logrotate.d/blue-team-mcp
```

```
/var/log/blue-team-mcp/audit.log /var/log/blue-team-mcp/investigation_history.jsonl {
    daily
    rotate 30
    maxsize 100M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 blueteam-mcp blueteam-mcp
    postrotate
        systemctl kill -s HUP blue-team-mcp.service 2>/dev/null || true
    endscript
}
```

```bash
# Verify rotation config
sudo logrotate -d /etc/logrotate.d/blue-team-mcp
```

#### 4.3 Configure Environment

Edit the environment file with production settings:

```bash
sudo nano /opt/blue-team-mcp/config.env
```

**Minimum production config:**

```bash
# Required — Wazuh Indexer (alert data)
export WAZUH_INDEXER_URL="https://wazuh-indexer:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="your_indexer_password"

# Optional — Wazuh Manager API (agent/rules/config)
export WAZUH_API_URL="https://wazuh-manager:55000"
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="your_api_password"

# Recommended — persistence
export BLUETEAM_AUDIT_LOG="/var/log/blue-team-mcp/audit.log"
export BLUETEAM_INVESTIGATION_HISTORY="/var/log/blue-team-mcp/investigation_history.jsonl"
export BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES="10000"

# Optional — rate limiting
export BLUETEAM_RATE_LIMIT="60"
```

#### 4.4 Health Check

Verify the server is running and responding:

```bash
# Check service status
sudo systemctl status blue-team-mcp

# View recent logs
sudo journalctl -u blue-team-mcp -f

# Test MCP endpoint
curl -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"health-check","version":"1.0"}}}'
```

#### 4.5 TLS Termination (nginx reverse proxy)

For production, put nginx in front with TLS:

```bash
sudo nano /etc/nginx/sites-available/blue-team-mcp
```

```nginx
server {
    listen 443 ssl http2;
    server_name mcp.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/mcp.yourdomain.com.pem;
    ssl_certificate_key /etc/ssl/private/mcp.yourdomain.com.key;

    # Allow larger responses (Wazuh alert batches can be large)
    proxy_buffering off;
    proxy_read_timeout 120s;

    location /mcp {
        proxy_pass http://127.0.0.1:8000/mcp;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/blue-team-mcp /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Client connection (after TLS setup):

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "url": "https://mcp.yourdomain.com/mcp",
      "transport": "streamable-http"
    }
  }
}
```

#### 4.6 Firewall

If binding to `0.0.0.0` (change `MCP_HOST` in the systemd unit):

```bash
# Option A — Direct exposure (not recommended without TLS)
sudo ufw allow 8000/tcp

# Option B — Behind nginx (recommended)
sudo ufw allow 443/tcp
```

#### 4.7 Monitoring

```bash
# Service uptime
systemctl status blue-team-mcp --no-pager | head -3

# Failed restarts in last hour
journalctl -u blue-team-mcp --since "1 hour ago" | grep -c "FAILED\|error"

# Disk usage
ls -lh /var/log/blue-team-mcp/
```

---

## Bulk Data Strategy — 3-Tier Retrieval

For large datasets (90+ days, 1M+ alerts), use the tiered approach to avoid
overloading the MCP transport:

| Tier | Tool | Coverage | Response size | Use case |
|---|---|---|---|---|
| **1 — Stats** | `wazuhAlertAggregateAnalysis`, `blueteamBaselineProfile`, `blueteamCalendarHeatmap`, `blueteamWazuhGeoDistribution` | ALL documents | ~2KB | "What happened?" — trends, top IPs, severity breakdown |
| **2 — Sample** | `blueteamWazuhIndexerSearch` with `max_scanned=10000` | First N documents with total count | ~500KB | "Show me representative alerts" |
| **3 — Export** | `blueteamWazuhExport` | ALL documents → server-side JSONL file | File path + stats | "I need every document for forensic analysis" |

**Tier 1 handles 90% of SOC workflows instantly.** Tier 3 streams documents
directly to disk via OpenSearch scroll API — no in-memory accumulation, safe
for millions of documents. The LLM receives the file path and reads slices
with `blueteamReadSyslog`.

```
1. Run Tier 1 first — get the big picture in 2KB
2. If suspicious, drill down with Tier 2 — get sample documents
3. For forensic dumps, use Tier 3 — server-side export to file
```

---

## Available Tools

All tools below are registered across the `mcp_server/` package. Tools not requiring a specific API key work out of the box; optional API keys unlock additional capabilities as noted.

### MCP Resources (auto-loaded by LLM at startup)

| Resource URI | Description |
|-------------|-------------|
| `wazuh://rules/taxonomy` | Wazuh rule catalog — rule IDs, levels, descriptions for alert triage context |
| `wazuh://mitre/attack` | MITRE ATT&CK framework mapping — 33 techniques, 12 tactics, 3-Sum category (A/B/C) mapping |

### Log Analysis
| Tool | Description |
|------|-------------|
| `blueteam_read_auth_log` | SSH/sudo/PAM events from auth.log |
| `blueteam_read_syslog` | General system events |
| `blueteam_read_web_log` | nginx/Apache access & error logs |
| `blueteam_journalctl` | Query any systemd unit's journal |

### Network Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_list_listening_ports` | All open/listening ports with process |
| `blueteam_list_connections` | Established TCP connections |
| `blueteam_capture_traffic` | Live packet capture via tcpdump |

### Wazuh SIEM
*All tools support cursor-based pagination where applicable — see [Cursor-Based Pagination](#cursor-based-pagination-bulk-data-without-hard-caps). `blueteam_wazuh_indexer_search`, `wazuh_domain_lookup`, and `wazuh_alert_focused_crawl` also support **auto-pagination** via the `max_scanned` parameter. `blueteam_wazuh_indexer_search` additionally supports **forensic mode** (`include_all_docs=True`) when `BLUETEAM_ALLOW_UNTRUNCATED=true`.*

| Tool | Description |
|------|-------------|
| `blueteam_wazuh_agents` | List all Wazuh agents — paginated via `cursor`/`limit` (up to 10,000/page) |
| `blueteam_wazuh_agents_summary` | Agent count by status (active/disconnected) |
| `blueteam_wazuh_manager_logs` | Manager daemon logs — paginated via `cursor`/`limit` (up to 1,000/page) |
| `blueteam_wazuh_alerts` | Security alerts from alerts.json — paginated via `cursor`/`limit` (up to 2,000/page) |
| `blueteam_wazuh_indexer_search` | Query OpenSearch for agent alerts/events — paginated via `cursor`/`limit` (up to 10,000/page). Set `max_scanned` for auto-pagination. |
| `wazuh_alert_aggregate_analysis` | 🆕 **Tier 1** — Full-period statistical analysis via `size:0` OpenSearch aggregations. Modes: topology, anomaly, correlation, trend, summary. **No document limit** |
| `wazuh_alert_dsl_query` | 🆕 **Tier 2** — Power-user escape hatch: submit raw OpenSearch DSL with `size:0` enforced. For custom aggregations not covered by Tier 1 |
| `wazuh_alert_focused_crawl` | 🆕 **Tier 3** — Surgical drill-down: retrieve representative alert samples for specific hot spots identified by Tiers 1 & 2 |
| `wazuh_email_lookup` | Find top-N compromised email addresses by scanning `full_log` + `data.account` fields (auto-paginates up to `max_scanned`) |
| `wazuh_domain_lookup` | Search alerts by domain name with cursor pagination and source IP aggregation. Set `max_scanned` for auto-pagination. |
| `wazuh_compromised_emails_analysis` | Correlate compromised emails with attacker IPs, optional Netra enrichment (auto-paginates per batch) |
| `wazuh_alert_timeline` | Time-bucketed alert aggregation using OpenSearch `date_histogram` — covers ALL matching alerts |
| `wazuh_attack_velocity` | Compare two time windows to detect attack acceleration/deceleration — covers ALL matching alerts |
| `three_sum_correlation` | **3-Sum APT Detection Engine**: Engine A (weighted intersection scoring) + Engine B (volumetric Z-score, median/MAD option, shoulder check) + **unified cross-engine scoring** + **multi-resolution analysis** (1h/24h/7d tiers). Auto-scaled bucket intervals, account lockout counter, `follow_up="threat_intel"`, degradation detection on Indexer failure. |
| `blueteam_wazuh_get_rules` | List Wazuh rules with optional ID filter — Manager API |
| `blueteam_wazuh_get_decoders` | List Wazuh decoders with optional name filter — Manager API |
| `blueteam_wazuh_get_groups` | List Wazuh agent groups — Manager API |
| `blueteam_wazuh_get_security_events` | Fetch Wazuh security events — Manager API |
| `blueteam_wazuh_get_cluster_nodes` | List Wazuh cluster nodes with version/type info — Manager API |

### Alert Enrichment & Analysis (Sprint 2-4)
| Tool | Description |
|------|-------------|
| `blueteam_wazuh_alert_summarize` | 🆕 **F-1** — IoC extraction + rule grouping + unusual UA flagging → compact digest |
| `blueteam_beacon_detect` | 🆕 **F-2** — Inter-arrival time analysis, CV-based beacon scoring, period estimation |
| `blueteam_attack_chain` | 🆕 **F-3** — Rule-to-rule transition graphs, kill-chain pattern matching (5 chains) |
| `blueteam_threat_card` | 🆕 **F-5** — Single-call threat report: alerts + CrowdSec/GreyNoise + MITRE + actions |
| `blueteam_wazuh_alert_compare` | 🆕 **F-6** — Side-by-side IP comparison via 0-doc aggregations with verdict |
| `blueteam_wazuh_geo_distribution` | 🆕 **G-2** — Country-level attack ranking (size:0, no docs fetched) |
| `blueteam_curated_threat_report` | 🆕 **G-3** — One-call filter→aggregate→enrich→report pipeline. 29 filter dims, 4 intel sources, compare/dedup/decay/deep modes |
| `blueteam_baseline_profile` | 🆕 — μ/σ/Z-score statistical baselining. "Is 4,821 alerts normal?" |
| `blueteam_calendar_heatmap` | 🆕 — Day×hour periodicity detection (30+ day windows, ASCII heatmap) |
| `blueteam_investigation_history` | 🆕 — JSONL-based IP verdict persistence. "Did we analyze this IP before?" |
| `blueteam_mark_investigated` | 🆕 — Record IP investigation verdict + notes (JSONL write) |
| `blueteam_false_positive_tracker` | 🆕 — Count FP verdicts per rule_id for rule tuning |
| `blueteam_investigation_summary` | 🆕 — Dashboard: IPs investigated, verdict breakdown |

### Threat Intelligence
| Tool | Description |
|------|-------------|
| `blueteam_lookup_ip_abuseipdb` | IP reputation via AbuseIPDB |
| `blueteam_lookup_hash_virustotal` | File hash lookup via VirusTotal |
| `blueteam_lookup_domain_virustotal` | Domain reputation via VirusTotal |

### Netra Threat Intelligence
### Argus Threat Intelligence
*Requires `ARGUS_API_KEY` and `ARGUS_BASE_URL`*

| Tool | Description |
|------|-------------|
| `argus_ip_lookup` | Multi-source IP lookup via Argus TI — aggregates VirusTotal, AbuseIPDB, CyberProtect, CrowdSec, ThreatBook, IPAPI, and local Argus reports in a single call |

### Netra Threat Intelligence
*Requires `NETRA_API_KEY`*

| Tool | Description |
|------|-------------|
| `netra_ip_analysis` | Multi-source IP analysis aggregating VirusTotal, AbuseIPDB, CrowdSec, IPAPI, and Argus with composite threat score and AI-generated insight |

### CrowdSec CTI
*Requires `CROWDSEC_API_KEY`*

| Tool | Description |
|------|-------------|
| `crowdsec_ip_reputation` | Single IP reputation via CrowdSec CTI Smoke API (behaviors, MITRE ATT&CK, CVEs) |
| `crowdsec_ip_reputation_bulk` | Batch reputation lookup for up to 10 IPs — **parallel execution** via `asyncio.gather()` + semaphore (configurable concurrency) |

### GreyNoise Community
*Free — no API key required*

| Tool | Description |
|------|-------------|
| `greynoise_ip_context` | Check if an IP is a known internet scanner (noise) or trusted business service (RIOT) |

### ThreatFox IOC Search
*Requires `THREATFOX_API_KEY`*

| Tool | Description |
|------|-------------|
| `threatfox_ioc_search` | Search ThreatFox by abuse.ch for malware-associated IOCs |
| `threatfox_ioc_search_bulk` | Concurrent multi-IOC lookup (max 25) |
| `blueteam_unified_threat_score` | Multi-source scoring (CrowdSec + ThreatFox + AbuseIPDB) |
| `blueteam_extract_iocs` | Extract IPs, domains, URLs, emails, hashes from alert text |

### MITRE ATT&CK & Threat Hunting

| Tool | Description |
|------|-------------|
| `blueteam_mitre_lookup` | Look up MITRE ATT&CK technique details or list techniques by tactic |
| `blueteam_threat_hunt` | 11 named threat hunting templates (PowerShell, LSASS, Kerberoasting, etc.) |

### Domain Investigation

| Tool | Description |
|------|-------------|
| `blueteam_whois_lookup` | RDAP domain registration lookup — free, no API key required |
| `blueteam_crtsh_lookup` | SSL certificate transparency search — find sibling domains |

### Cross-Tool Investigation

| Tool | Description |
|------|-------------|
| `blueteam_investigate_ip` | One-call IP triage: alert profile + timeline + geo + agent breakdown |
| `blueteam_wazuh_export` | 🆕 Server-side export — streams ALL matching alerts to JSONL file via scroll API |

### Vulnerability & Compliance Scanning

| Tool | Description |
|------|-------------|
| `blueteam_wazuh_vulnerabilities` | 🆕 Query CVE findings from Wazuh vulnerability scanner |
| `blueteam_wazuh_syscheck` | 🆕 File Integrity Monitoring - track file additions, modifications, deletions |
| `blueteam_wazuh_compliance` | 🆕 Compliance framework summary (CIS, PCI DSS, GDPR, HIPAA, NIST 800-53) |
| `blueteam_wazuh_geo_heatmap` | 🆕 Attack coordinate + city-level geo heatmap for visualization |
| `blueteam_semantic_search` | 🆕 BM25 semantic search - natural language queries against Wazuh rules |
| `blueteam_prompt_route` | 🆕 BM25 prompt-to-tool routing — maps natural-language prompts to ranked MCP tools |
| `blueteam_check_webshell` | 🆕 Webshell checker — curl + 20-signature scan against forensic URLs |
| `blueteam_export_report` | 🆕 SOC report deliverables - generate .docx / .xlsx / .pptx via officecli |
| `blueteam_stix_analyze` | 🆕 MITRE ATT&CK STIX correlation - map techniques, threat actors, campaigns, mitigations |

### Fail2Ban
| Tool | Description |
|------|-------------|
| `blueteam_fail2ban_status` | List all jails and ban counts |
| `blueteam_fail2ban_jail_status` | Detailed status of a specific jail |
| `blueteam_fail2ban_unban` | Unban an IP from a jail |

### File Integrity
| Tool | Description |
|------|-------------|
| `blueteam_hash_file` | Hash any file (MD5/SHA1/SHA256/SHA512) |
| `blueteam_find_suid_files` | Find unexpected SUID/SGID binaries |
| `blueteam_find_world_writable` | Find world-writable files (persistence indicator) |
| `blueteam_rootkit_scan` | Run rkhunter or chkrootkit |

### System Hardening
| Tool | Description |
|------|-------------|
| `blueteam_lynis_audit` | Full Lynis hardening audit |
| `blueteam_check_updates` | Check for pending security updates |
| `blueteam_check_open_firewall` | View ufw/nftables/iptables rules |

### User & Session Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_who_is_logged_in` | Active user sessions with source IPs |
| `blueteam_last_logins` | Login history (last 50) |
| `blueteam_failed_logins` | Failed login attempts |
| `blueteam_sudo_history` | Sudo command usage |
| `blueteam_list_users` | All local accounts with risk flags |
| `blueteam_check_ssh_authorized_keys` | All authorized_keys files |

### Process & Persistence
| Tool | Description |
|------|-------------|
| `blueteam_list_processes` | All running processes |
| `blueteam_list_cron_jobs` | System and user cron jobs |

### System Health
| Tool | Description |
|------|-------------|
| `blueteam_system_health` | Uptime, disk, memory, CPU load |

---

## Example Prompts / Contoh Prompt

Once connected via Claude Desktop, you can ask / Setelah terkoneksi:

### 🔍 Investigation & Triage / Investigasi & Triase

```
"A new alert came in from 103.166.210.53. Investigate this IP comprehensively."
→ blueteam_investigate_ip(srcip="103.166.210.53", since="24h")

"Ada alert baru dari IP 103.166.210.53. Selidiki IP ini secara menyeluruh."
→ blueteam_investigate_ip(srcip="103.166.210.53", since="24h")

"Show me all alerts from agent TheZoo-host4 in the last hour."
→ blueteam_wazuh_alerts(agent_name="TheZoo-host4", since="1h", limit=100)

"Tampilkan semua alert dari agen TheZoo-host4 dalam 1 jam terakhir."
→ blueteam_wazuh_alerts(agent_name="TheZoo-host4", since="1h", limit=100)
```

### 🧠 Semantic Search / Pencarian Semantik

```
"Find Wazuh rules related to credential theft and show matching alerts."
→ blueteam_semantic_search(query="credential theft", source="rules")

"Cari rule Wazuh yang berkaitan dengan serangan webshell."
→ blueteam_semantic_search(query="serangan webshell pada server", source="rules")

"Search actual alerts for ransomware activity in the last 7 days."
→ blueteam_semantic_search(query="ransomware encryption", source="alerts", since="7d")

"Cari alert yang mengandung indikasi perjudian dalam 30 hari terakhir."
→ blueteam_semantic_search(query="judi online gambling", source="alerts", since="30d")
```

### 📊 Aggregate Analysis / Analisis Agregat

```
"Show me the attack topology for the last 24 hours — top IPs, rules, agents."
→ wazuh_alert_aggregate_analysis(mode="topology", since="24h", top_n=30)

"Tampilkan tren serangan 7 hari terakhir — anomali, korelasi, summary."
→ wazuh_alert_aggregate_analysis(mode="trend", since="7d")

"What's the baseline alert volume? Is 4,821 alerts per hour normal?"
→ blueteam_baseline_profile(metric="alert_volume", window="7d")

"Apakah 4.821 alert per jam itu normal? Cek baseline."
→ blueteam_baseline_profile(metric="alert_volume", window="7d")

"Show a calendar heatmap of attacks for the last 30 days."
→ blueteam_calendar_heatmap(days=30)
```

### 🌍 Geo Analysis / Analisis Geografis

```
"Show top attacking countries in the last 24 hours."
→ blueteam_wazuh_geo_distribution(since="24h", top_n=15)

"Tampilkan kota asal serangan terbanyak."
→ blueteam_wazuh_geo_distribution(since="24h", granularity="city")

"Generate a geo heatmap with coordinates for the last 7 days."
→ blueteam_wazuh_geo_heatmap(since="7d", response_format="json")
```

### 🔬 Threat Hunting / Perburuan Ancaman

```
"Hunt for encoded PowerShell commands in the last 24 hours."
→ blueteam_threat_hunt(template="encoded_powershell", since="24h")

"Cari indikasi credential dumping — Mimikatz, LSASS, procdump."
→ blueteam_threat_hunt(template="credential_dumping", since="7d")

"Check for lateral movement from a specific IP."
→ blueteam_threat_hunt(template="lateral_movement", srcip="10.0.0.55", since="3d")

"Deteksi C2 beaconing — koneksi berkala ke server musuh."
→ blueteam_threat_hunt(template="c2_beacon", since="24h")
```

### 🛡️ Threat Intelligence / Intelijen Ancaman

```
"Look up 185.220.101.1 on CrowdSec, ThreatFox, and AbuseIPDB."
→ crowdsec_ip_reputation(ip="185.220.101.1")
→ threatfox_ioc_search(search_term="185.220.101.1")

"Get a unified threat score for 103.166.210.53 from all sources."
→ blueteam_unified_threat_score(ip="103.166.210.53")

"Check 5 IPs against CrowdSec in bulk."
→ crowdsec_ip_reputation_bulk(ips=["1.2.3.4","5.6.7.8","9.10.11.12","13.14.15.16","200.1.2.3"])

"Check if 71.6.135.131 is a known internet scanner with GreyNoise."
→ greynoise_ip_context(ip="71.6.135.131")

"Extract all IOCs from this alert text."
→ blueteam_extract_iocs(text="{alert_full_log}")
```

### 🌐 Domain Investigation / Investigasi Domain

```
"Look up who owns evil-c2.net via RDAP."
→ blueteam_whois_lookup(domain="evil-c2.net")

"Cari semua subdomain dan sibling domain dari tangerangkota.go.id via crt.sh."
→ blueteam_crtsh_lookup(domain="tangerangkota.go.id")

"Search all Wazuh alerts for a specific domain."
→ wazuh_domain_lookup(domain="tangerangkota.go.id", since="7d")
```

### 🏥 Host Forensics / Forensik Host

```
"Check the last 2 hours of auth.log for brute force attempts."
→ blueteam_read_auth_log(filter="Failed password", lines=200)

"Show all listening ports. Any unexpected services?"
→ blueteam_list_listening_ports()

"Cek semua user yang sedang login sekarang."
→ blueteam_who_is_logged_in()

"Find all SUID binaries that aren't standard."
→ blueteam_find_suid_files()

"Run a Lynis hardening audit and give me the top 5 items."
→ blueteam_lynis_audit()

"Hash /usr/bin/sshd and check against VirusTotal."
→ blueteam_hash_file(path="/usr/bin/sshd")
→ blueteam_lookup_hash_virustotal(hash="{result}")
```

### 🔐 Vulnerability & Compliance / Kerentanan & Kepatuhan

```
"Show all CVE findings in the last 30 days."
→ blueteam_wazuh_vulnerabilities(since="30d")

"Tampilkan temuan CVE critical saja."
→ blueteam_wazuh_vulnerabilities(severity="Critical", since="90d")

"Show File Integrity Monitoring events for /etc/* in the last 24h."
→ blueteam_wazuh_syscheck(path_filter="/etc/*", since="24h")

"Tampilkan ringkasan kepatuhan CIS."
→ blueteam_wazuh_compliance(framework="cis", since="30d")

"Check PCI DSS compliance status across all agents."
→ blueteam_wazuh_compliance(framework="pci_dss", since="90d")
```

### 📡 Bulk Data & Export / Data Masal & Ekspor

```
"Export all alerts for the last 7 days to a JSONL file."
→ blueteam_wazuh_export(since="7d")

"Ekspor semua alert 90 hari untuk investigasi forensik."
→ blueteam_wazuh_export(since="90d")

"Enumerate all 1,500 Wazuh agents with cursor pagination."
→ blueteam_wazuh_agents(limit=100, cursor={next_cursor})

"Search the indexer with keyword and iterate through all results."
→ blueteam_wazuh_indexer_search(keyword="locked OR brute", since="24h", max_scanned=10000)
```

### 🧪 APT Detection / Deteksi APT

```
"Run 3-Sum correlation for the last hour with threat intel enrichment."
→ three_sum_correlation(time_window_minutes=60, follow_up="threat_intel")

"Jalankan 3-Sum deteksi APT dengan window 24 jam."
→ three_sum_correlation(time_window_minutes=1440, engine_a_enabled=true, engine_b_enabled=true)

"Analyze attack chain progression for IP 103.166.210.53."
→ blueteam_attack_chain(srcip="103.166.210.53", since="7d")

"Detect C2 beaconing pattern for a suspicious IP."
→ blueteam_beacon_detect(srcip="185.220.101.1", since="24h")
```

### 📋 SOC Daily Report / Laporan Harian SOC (24 Jam)

#### Format DOCX (via OfficeCLI + Sangfor Blocklist)

```
⚠️ EXECUTION RULES:
- redaction_policy="protect_victim" HANYA diterima oleh 5 tool:
    blueteam_curated_threat_report, blueteam_wazuh_alert_summarize,
    blueteam_wazuh_indexer_search, three_sum_correlation,
    blueteam_investigate_ip
- blueteam_wazuh_export menggunakan bypass_redaction (bukan redaction_policy) —
  hanya untuk forensic export ke disk (LLM tidak melihat raw data).
- Tool lain TIDAK MENERIMA redaction_policy — JANGAN kirim parameter itu.
  Jika tool menolak "extra_forbidden", hapus redaction_policy dan panggil ulang.
- blueteam_export_report TIDAK mendukung reveal_owned.
- blueteam_export_report HANYA mendukung format docx/xlsx/pptx.
- Path export WAJIB: /var/log/blue-team-mcp/exports/

⚠️ DUA TIER UNMASKING (pahami bedanya):

TIER 1 — reveal_owned=true (AMAN untuk LLM, khusus MILIK SENDIRI):
- HANYA membuka aset MILIK SENDIRI: *.tangerangkota.go.id + @tangerangkota.go.id
- Ini data organisasi Anda, BUKAN PII pihak ketiga.
- GUNAKAN untuk forensik: identifikasi subdomain diserang + email dinas locked.
- Tool yang mendukung reveal_owned (12 tool — JANGAN batasi ke 3):
  blueteam_curated_threat_report, blueteam_wazuh_alert_summarize,
  blueteam_threat_card, three_sum_correlation, blueteam_investigate_ip,
  wazuh_alert_aggregate_analysis, wazuh_domain_lookup, wazuh_email_lookup,
  wazuh_alert_focused_crawl, wazuh_alert_timeline, wazuh_attack_velocity,
  blueteam_wazuh_vulnerabilities.

TIER 2 — bypass_redaction + forensic_token (HUMAN ONLY):
- Membuka SEMUA data mentah (attacker payload, seluruh domain/email).
- LLM TIDAK PERNAH melihat ini — hanya operator dengan token.
- blueteam_wazuh_export menulis ke disk, LLM hanya terima file path.

⚠️ MODEL DEFAULT (protect_victim — WAJIB untuk semua langkah analisis):
- LLM MELIHAT: attacker IP publik, attacker payload/exploit, rule, severity, mitre.
- LLM TIDAK MELIHAT: email dinas (@tangerangkota.go.id), subdomain internal
  (*.tangerangkota.go.id), private IP (RFC1918), path internal.
- Ini model paling aman: PII internal terlindung, data attacker utuh untuk investigasi.

⚠️ PASS FORENSIC (opsional — setelah analisis selesai):
- Jalankan ulang tool berikut dengan reveal_owned=true untuk atribusi aset milik sendiri:
  blueteam_curated_threat_report(..., reveal_owned=true)
  wazuh_domain_lookup(..., reveal_owned=true)   ← BUKA subdomain asli (Tier 1)
  wazuh_email_lookup(..., reveal_owned=true)    ← BUKA email dinas asli (Tier 1)
- Hasil pass forensic: subdomain + email dinas asli untuk identifikasi target serangan.
- PENTING: reveal_owned=true = Tier 1 (AMAN, aset milik sendiri).
  JANGAN salah klasifikasi sebagai Tier 2 (forensic_token). Tier 2 hanya untuk
  attacker payload + data pihak ketiga.

⚠️ FORENSIC UNMASKING (tanpa leak ke LLM Provider):
- blueteam_wazuh_export dengan bypass_redaction=true + forensic_token
  menulis raw data LANGSUNG ke disk server — LLM HANYA menerima file path.
- Analis membaca file export langsung di server — email/subdomain asli
  TIDAK PERNAH melewati LLM provider.
- blueteam_export_report TETAP menggunakan data ter-redaksi dari analisis.
- Syarat: BLUETEAM_ALLOW_FORENSIC_BYPASS=true + BLUETEAM_FORENSIC_TOKEN diset.

LANGKAH 0 — BM25 Prompt Routing (opsional):
blueteam_prompt_route(prompt="<isi_prompt>", mode="buckets")
→ Petakan prompt ke tool yang paling relevan.

LANGKAH 1 — Gambaran Menyeluruh (SEMUA serangan):
blueteam_curated_threat_report(since="24h", investigation_depth="deep",
  response_format="json", redaction_policy="protect_victim")
→ Dapatkan seluruh serangan: top attacker IP, rule, severity, mitre tactics,
  geo distribution, time decay analysis, dan IOC.

LANGKAH 1b — Forensik Subdomain & Email Dinas (reveal_owned — TIER 1):
blueteam_wazuh_indexer_search(
  keyword="tangerangkota.go.id", since="24h",
  redaction_policy="protect_victim", reveal_owned=true,
  response_format="json")
→ LLM MELIHAT subdomain asli (ppid.tangerangkota.go.id, dll) + email dinas asli.
→ Gunakan untuk: identifikasi asset yang diserang, mapping attacker → target.
→ Ini data MILIK SENDIRI — aman untuk LLM (bukan PII pihak ketiga).

LANGKAH 2 — Subdomain Paling Diserang (reveal_owned — TIER 1):
wazuh_domain_lookup(domain="tangerangkota.go.id", since="24h",
  response_format="json", max_scanned=10000, reveal_owned=true)
→ reveal_owned=true MEMBUKA subdomain asli (bukan masked).
→ Ini aset MILIK SENDIRI — Tier 1, BUKAN Tier 2. TIDAK butuh forensic_token.
→ Urutkan seluruh subdomain berdasarkan jumlah serangan.

LANGKAH 3 — Threat Card + Attack Chain per Attacker:
Untuk SETIAP top attacker IP (minimal top 10) dari langkah 1-2:
  blueteam_threat_card(srcip=<ip>, since="24h")
  blueteam_attack_chain(srcip=<ip>, since="24h")
→ Threat intel, kill-chain progression, rule transition graph.

LANGKAH 4 — Sangfor Blocklist Check (firewall status):
sangfor_blocklist_list(response_format="json")
→ Dapatkan seluruh IP yang sudah di-block oleh Sangfor.
Untuk SETIAP top attacker IP dari langkah 1-2:
  sangfor_blocklist_check(ip=<ip>, response_format="json")
→ Cek apakah IP attacker sudah ada di blocklist Sangfor.
→ Tandai IP yang BELUM di-block untuk tindakan lanjutan.

LANGKAH 5 — Ekstrak IOC (seluruh jenis serangan):
blueteam_extract_iocs(text=<seluruh_alert_text_dari_langkah_1>)
→ Ekstrak IP, domain, URL, email, hash dari SEMUA alert.

LANGKAH 6 — Argus (auth success IPs):
wazuh_alert_aggregate_analysis(mode="summary", since="24h",
  response_format="json")
→ Filter seluruh IP dengan authentication_success, lalu:
  argus_ip_lookup(ip=<ip>) untuk setiap IP.

LANGKAH 7 — 3-Sum APT + ThreatFox + CrowdSec:
three_sum_correlation(time_window_minutes=1440, follow_up="threat_intel",
  multi_resolution=true, response_format="json",
  redaction_policy="protect_victim")
→ Deteksi APT multi-stage + auto-enrich seluruh trigger IP.

LANGKAH 8 — NetworkX Attack Graph (seluruh IOC):
blueteam_attack_graph(since_days=30, top_n=20, response_format="json")
→ Cluster kampanye, hub/bridge IOCs, edge betweenness, suspicion rank.
blueteam_campaign_watch(response_format="json")
→ Diff snapshot sekarang vs sebelumnya: new_clusters, growth events.

LANGKAH 9 — LangGraph Investigation (seluruh top attacker):
Untuk SETIAP top attacker IP (minimal top 5):
blueteam_investigation_workflow(
  alert_text="<dari langkah 1>", srcip=<ip>,
  window="24h", use_attack_graph=true,
  generate_report=false, record_verdict=true,
  verdict_label="suspicious")
→ extract → enrich → 3-Sum → analytics (graph ∥ killchain) →
  baseline → verdict. State bertahan jika BLUETEAM_LANGGRAPH_DB diset.

LANGKAH 10 — LangGraph Playbook (seluruh alert anomali):
Jika 3-Sum mendeteksi anomali (severity ≥ LOW):
blueteam_playbook_run(
  alert_text="<dari langkah 1>",
  rule_groups="<dari hasil 3-Sum / curated report>",
  window="24h", use_attack_graph=true, generate_report=false)
→ select template → run hunt → supervise → retry ladder → investigate.

LANGKAH 11 — Email Locked + Analisa:
wazuh_compromised_emails_analysis(since="24h", response_format="json")
→ Seluruh email "locked" + argus_ip_lookup + threatfox_ioc_search.

LANGKAH 11b — Email Dinas Locked (reveal_owned — TIER 1):
wazuh_compromised_emails_analysis(since="24h", reveal_owned=true,
  response_format="json")
→ LLM MELIHAT email dinas asli yang locked (bukan masked).
→ Cross-reference dengan attacker IP penyebab lock.
→ Ini email MILIK SENDIRI — aman untuk LLM.

LANGKAH 12 — Semantic Search (seluruh pola serangan):
blueteam_semantic_search(
  query="<pola_serangan_dari_langkah_1>",
  source="alerts", since="24h", top_k=30,
  response_format="json")
→ BM25 ranking: temukan seluruh alert dengan pola serangan dominan.

LANGKAH 13 — MITRE ATT&CK (seluruh top attacker):
Untuk setiap top attacker IP (minimal top 5):
blueteam_stix_killchain(srcip=<ip>, since="24h")
→ Map technique ID ke ATT&CK phases + actors, campaigns, mitigations.

LANGKAH 14 — Geo Heatmap:
blueteam_wazuh_geo_heatmap(since="24h", response_format="json")

LANGKAH 15 — Laporan Akhir (DOCX):
blueteam_export_report(format="docx",
  title="Laporan Serangan Siber 24 Jam — Infra Pemkot Tangerang",
  path="/var/log/blue-team-mcp/exports/laporan_24jam_{{date}}.docx",
  docx_sections=[
    {"heading": "Ringkasan Eksekutif",
     "paragraphs": ["<dari langkah 1: total, top attacker, severity>"]},
    {"heading": "Subdomain Diserang + Attacker IP",
     "paragraphs": ["<dari langkah 2-3>"]},
    {"heading": "Sangfor Blocklist Status",
     "paragraphs": ["<dari langkah 4: blocked vs unblocked IPs>"]},
    {"heading": "IOC (Seluruh Jenis Serangan)",
     "paragraphs": ["<dari langkah 5>"]},
    {"heading": "Auth Success + Argus",
     "paragraphs": ["<dari langkah 6>"]},
    {"heading": "3-Sum APT Detection (Multi-Resolution)",
     "paragraphs": ["<dari langkah 7: persistent, slow_burn, burst_only>"]},
    {"heading": "Attack Graph — NetworkX",
     "paragraphs": ["<dari langkah 8>"]},
    {"heading": "LangGraph Investigation + Playbook",
     "paragraphs": ["<dari langkah 9-10>"]},
    {"heading": "Email Locked + Analisa Threat Intel",
     "paragraphs": ["<dari langkah 11>"]},
    {"heading": "Semantic Search — Pola Serangan Dominan",
     "paragraphs": ["<dari langkah 12: BM25 ranked results>"]},
    {"heading": "MITRE ATT&CK Kill Chain",
     "paragraphs": ["<dari langkah 13>"]},
    {"heading": "Geo Heatmap",
     "paragraphs": ["<dari langkah 14>"]},
    {"heading": "Webshell Check (Forensic)",
     "paragraphs": ["<dari langkah 17: blueteam_check_webshell results>"]}
  ])

LANGKAH 16 — Forensic Export (opsional, UNTUK ANALIS):
blueteam_wazuh_export(
  since="24h",
  bypass_redaction=true,
  forensic_token="<BLUETEAM_FORENSIC_TOKEN>",
  path="/var/log/blue-team-mcp/exports/forensic_24jam_{{date}}.jsonl")
→ Raw data ke disk — LLM hanya terima {"path": "...", "total": N}.

LANGKAH 17 — Webshell Check (setelah forensic unmask):
Analis membaca file export, ekstrak URL mencurigakan:
  cat /var/log/blue-team-mcp/exports/forensic_24jam_*.jsonl \
    | jq -r '.data.url' | sort -u | grep -v '^-$'
Untuk SETIAP URL mencurigakan:
  blueteam_check_webshell(url="<url>", timeout=10)
→ Verdict: CONFIRMED / LOGIN_PAGE (klasifikasi LLM) / SUSPICIOUS / CLEAN.
→ CONFIRMED → URL auto-registered sebagai attacker IOC.
→ LOGIN_PAGE → LLM analisa HTML context: shell login atau aplikasi sah?
→ Jika shell login terkonfirmasi, register sebagai attacker IOC.
→ Tambahkan hasil ke laporan DOCX: "Webshell Check Results".
```

#### Format Markdown (tanpa OfficeCLI — LLM compose langsung)

```
⚠️ EXECUTION RULES:
- Sama dengan rules di atas (redaction_policy, reveal_owned, forensic).
- TIDAK menggunakan blueteam_export_report.
- LLM menyusun laporan markdown langsung dari hasil langkah 1-14.
- Format output: markdown dengan heading, table, code block.
- Simpan sebagai file .md di akhir respons.

LANGKAH 1-14 — Jalankan SEMUA langkah analisis (sama seperti format DOCX).

OUTPUT — LLM menyusun laporan markdown dengan struktur:

# Laporan Serangan Siber 24 Jam — Infra Pemkot Tangerang
**Periode**: {{since}} — {{until}} | **Total Serangan**: {{total}}

## Ringkasan Eksekutif
<dari langkah 1>

## Subdomain Diserang + Attacker IP
<dari langkah 2-3>

## Sangfor Blocklist Status
| IP | Blocked | Action Needed |
|----|---------|---------------|
<dari langkah 4: blocked vs unblocked IPs>

## IOC (Seluruh Jenis Serangan)
<dari langkah 5>

## Auth Success + Argus
<dari langkah 6>

## 3-Sum APT Detection (Multi-Resolution)
- **Persistent**: <count> IPs — high confidence
- **Slow Burn (7d only)**: <count> IPs
- **Burst (1h only)**: <count> IPs — likely noise
<dari langkah 7>

## Attack Graph — NetworkX
<dari langkah 8>

## LangGraph Investigation + Playbook
<dari langkah 9-10>

## Email Locked + Analisa Threat Intel
<dari langkah 11>

## Semantic Search — Pola Serangan Dominan
<dari langkah 12>

## MITRE ATT&CK Kill Chain
<dari langkah 13>

## Geo Heatmap
<dari langkah 14>

## Webshell Check (Forensic)
| URL | HTTP Status | Verdict | Shell Family |
|-----|------------|---------|-------------|
<dari langkah 17: blueteam_check_webshell results>

---
*Laporan digenerate otomatis oleh Blue Team MCP Server — TangerangKota-CSIRT*
```

### 🕸️ NetworkX Attack Graph & LangGraph Workflows

Gunakan `blueteam_attack_graph`, `blueteam_campaign_watch`,
`blueteam_investigation_workflow`, dan `blueteam_playbook_run`
untuk analisis graf serangan dan otomatisasi investigasi.

```
⚠️ EXECUTION RULES:
- Gunakan blueteam_prompt_route terlebih dahulu untuk memetakan prompt ke tool yang tepat.
- blueteam_investigation_workflow dan blueteam_playbook_run menggunakan
  LangGraph stateful workflows — state bertahan antar restart jika
  BLUETEAM_LANGGRAPH_DB dikonfigurasi.

--- NetworkX Attack Graph ---

"Tampilkan attack graph 30 hari terakhir — cluster kampanye, hub, bridge IOCs."
→ blueteam_attack_graph(since_days=30, top_n=10, response_format="json")

"Analisis suspicion rank — IOC mana yang paling dekat ke confirmed attacker?"
→ blueteam_attack_graph(since_days=30, top_n=20, response_format="json")
→ Fokus pada top_suspicion dan top_edge_bridges.

"Bandingkan campaign snapshot sekarang vs sebelumnya — ada cluster baru?"
→ blueteam_campaign_watch(response_format="json")
→ Periksa new_clusters dan growth events.

"Cari jalur terpendek antara dua IOC dalam attack graph."
→ blueteam_attack_graph(since_days=30, response_format="json")
→ Gunakan shortest_path_between(a="<ip1>", b="<ip2>") dari hasil.

--- LangGraph Investigation Workflow ---

"Jalankan investigasi otomatis untuk IP <isi_srcip>"
→ blueteam_investigation_workflow(
    alert_text="<isi_alert>",
    srcip="<ip>",
    window="24h",
    use_attack_graph=true,
    generate_report=true,
    record_verdict=true,
    verdict_label="suspicious")

"Workflow lengkap: extract IOC → enrich → 3-Sum correlate →
  analytics (graph ∥ killchain) → baseline → report → verdict."
→ Semua langkah berjalan otomatis dalam satu panggilan.
→ Gunakan BLUETEAM_LANGGRAPH_DB untuk persistensi state.

--- LangGraph Playbook Runner ---

"Jalankan playbook untuk alert credential dumping."
→ blueteam_playbook_run(
    alert_text="<isi_alert>",
    rule_id="60106",
    technique="T1003",
    rule_groups="credential,mimikatz,lsass",
    window="24h",
    use_attack_graph=true,
    generate_report=true)

"Playbook: select template → run hunt → supervise → retry ladder
  (3 fallback templates) → dispatch investigation workflow."
→ Gunakan blueteam_prompt_route untuk memilih template yang tepat.
→ Retry ladder: targeted → c2_beacon → lateral_movement → END.
```

### 🔎 MITRE ATT&CK / Taktik MITRE

```
"What MITRE techniques map to Credential Access?"
→ blueteam_mitre_lookup(tactic="Credential Access")

"Apa itu T1003? Jelaskan tekniknya."
→ blueteam_mitre_lookup(technique_id="T1003")
```

---

## MAESTRO Framework Alignment (currently for dev only)

This server aligns with the [CSA MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) framework for agentic AI security.

### Optional: Audit Logging (Repudiation Mitigation)

Enable audit logging to record tool invocations:

```bash
export BLUETEAM_AUDIT_LOG=/var/log/blue-team-mcp/audit.log
```

Ensure log rotation (e.g., logrotate) to prevent unbounded growth.

### Optional: Rate Limiting (DoS Mitigation)

Limit tool calls per minute:

```bash
export BLUETEAM_RATE_LIMIT=60
```

---

## Security Notes

### Redaction & Privacy Policy (`protect_victim` mode)

All alert data returned to the LLM passes through `_redact_alert_data()` — a six-layer
pipeline whose **Layer 1 (credential stripping) is never bypassable**, including inside
attacker payloads. The pipeline is policy-driven (`BLUETEAM_REDACTION_POLICY` env, default
`full`; per-call `redaction_policy` field on tool input models overrides it):

| Policy | Effect |
|--------|--------|
| `full` (default) | Shape-based masking: emails, private IPs, **all** domains, paths, UAs |
| `protect_victim` | Masks **only victim-owned indicators** — emails/domains at `BLUETEAM_OWNED_DOMAINS` (e.g. `tangerangkota.go.id`), private IPs, paths, identity fields (`account`/`srcuser`/`dstuser`/`user`/`username`), `agent.name`. **Attacker public IPs, attacker domains/emails, and payload contents stay intact.** |
| `raw` | Layer 1 credential strip only — **hard-gated** behind `BLUETEAM_ALLOW_FORENSIC_BYPASS` (default `false`); raises otherwise |

- Attacker-IOC registry (`mcp_server/core/attacker_registry.py`): 3-Sum Engine A triggers,
  CrowdSec/ThreatFox enrichment, and `true_positive` verdicts exempt registered IOCs from
  shape-based masking in any mode (never from Layer 1).
- Recommended deployment for SOC work:
  `BLUETEAM_REDACTION_POLICY=protect_victim BLUETEAM_OWNED_DOMAINS=tangerangkota.go.id`
- `bypass_redaction=True` / `redaction_policy="raw"` is **LLM-callable but gated** — it
  fails loudly unless the operator sets `BLUETEAM_ALLOW_FORENSIC_BYPASS=true`. Every bypass
  is audit-logged (`forensic_bypass_response` with response SHA-256).

### Operational notes

- The MCP server runs with **whatever privileges the SSH user has**. Running as a dedicated low-privilege user (with sudo for specific tools) is recommended for production.
- Threat intel tools make **outbound API calls** to:
  - AbuseIPDB (`api.abuseipdb.com`)
  - VirusTotal (`www.virustotal.com`)
  - CrowdSec CTI (`cti.api.crowdsec.net`) — requires `CROWDSEC_API_KEY`
  - GreyNoise Community (`api.greynoise.io`) — free, no auth required
  Ensure outbound HTTPS to these endpoints is acceptable in your environment.
- `blueteam_capture_traffic` requires `CAP_NET_RAW` or root. The setup script attempts to grant this to tcpdump via `setcap`.
- Log files under `/var/log/` often require root or membership in the `adm` group to read. Add your SSH user to the `adm` group: `usermod -aG adm youruser`
- **Path restrictions:** `blueteam_hash_file` allows paths under `/var`, `/etc`, `/home`, `/opt`, `/usr` (configurable via `BLUETEAM_ALLOWED_PATHS`). `blueteam_capture_traffic` writes pcap files only under `BLUETEAM_CAPTURE_DIR` (default `/tmp`).

---

## Graph Engineering & IOC Intelligence

The platform layers networkx and langgraph over the 92-tool core:

### Attack graph (networkx) — `blueteam_attack_graph`
Builds an attacker relationship graph from the IOC store + attacker registry:
nodes = IOCs (with decay weights + confirmed flags) + STIX techniques/actors;
edges = co-occurrence (IOCs seen in the same extraction/trigger batch) + STIX.
Reports campaign clusters (connected components), hub IOCs (degree), bridge IOCs
(betweenness), **suspicion-ranked unconfirmed IOCs** (personalized PageRank seeded
on confirmed attackers), and shortest paths (e.g. srcip → actor).

### Campaign watch — `blueteam_campaign_watch`
Snapshots attack-graph components to `BLUETEAM_CAMPAIGN_SNAPSHOTS` (JSONL) and
diffs against the previous run: **new clusters** and **growing clusters** (with the
added IOCs) — active-campaign expansion detection.

### IOC lifecycle — `blueteam_ioc_lifecycle`
JSONL store (`BLUETEAM_IOC_STORE`) of discovered IOCs with time-decayed recency
scoring (7-day half-life). Fed by `blueteam_extract_iocs` and 3-Sum Engine A.
Auto-promotes consistently-observed IPs to the attacker registry when
`BLUETEAM_AUTO_PROMOTE_IPS=true`.

### STIX kill-chain — `blueteam_stix_killchain`
Per-srcip ATT&CK chain from observed `rule.mitre.id` mapped through the MITRE
STIX graph, ordered by kill-chain phase, annotated with actors/campaigns/mitigations.

### LangGraph workflows
- `blueteam_investigation_workflow` — stateful graph: extract → enrich → correlate →
  attack graph → kill-chain → baseline drift → report/verdict (conditional routing,
  graceful degradation).
- `blueteam_playbook_run` — alert-driven playbook runner (langgraph supervisor):
  selects a threat-hunt template from the alert context (MITRE > rule groups >
  fallback), runs the hunt, retries once with the generic `c2_beacon` template if
  empty, then dispatches the investigation workflow for the top srcip.

### 3-Sum graph integration — `three_sum_correlation(use_attack_graph=true)`
Engine A consumes the attack graph: **cluster-aware intersection** (a campaign
cluster spanning all 3 categories triggers even when no single IP does), **PPR
suspicion boost**, and a **registry-confirmed IOC bonus**. Engine B gains the
`engine_b_sparse_floor` sparse-category guard.
The LangGraph workflows (`blueteam_investigation_workflow`, `blueteam_playbook_run`)
default `use_attack_graph=true` — the auto-pipelines run campaign-level APT
detection out of the box.
Engine A consumes the attack graph: **cluster-aware intersection** (a campaign
cluster spanning all 3 categories triggers even when no single IP does), **PPR
suspicion boost**, and a **registry-confirmed IOC bonus**. Engine B gains the
`engine_b_sparse_floor` sparse-category guard.

### Baseline drift — `blueteam_baseline_drift`
Current window vs. the preceding same-length baseline via Z-score (σ = 0 guard,
conservative Z ≥ 2.5). Flags anomalous alert-volume buckets.

### Metrics — `metrics://prometheus` (+ `metrics://prometheus/json`)
Prometheus text exposition: tool call counters, pipeline durations, redaction-gate
failures, rate-limit hits, attacker-registry and IOC-store gauges.

## LLM Reference Prompt

Copy the block below into your local LLM (Claude Desktop, Ollama, LM Studio, etc.) that is
connected to this MCP server. It teaches the model the full tool surface (97 tools + 4
resources) and the standard SOC workflows.

```text
You are a blue-team SOC analyst operating the Blue Team Wazuh MCP server (97 tools).
Be precise, evidence-based, and never fabricate API fields. Follow the redacted-but-real
protocol: rely on masked values + forensic hashes by default; only expose raw data when the
operator explicitly asks.

## Tool groups and when to use them

1. WAZUH SIEM — blueteam_wazuh_alerts, blueteam_wazuh_indexer_search (pagination via
   next_cursor), blueteam_wazuh_agents (+summary), blueteam_wazuh_rules,
   wazuh_alert_dsl_query (custom aggregations), wazuh_alert_focused_crawl, blueteam_wazuh_export.
2. DETECTION ANALYTICS — wazuh_alert_aggregate_analysis, blueteam_wazuh_alert_summarize,
   blueteam_alert_compare, wazuh_alert_timeline, wazuh_attack_velocity,
   blueteam_calendar_heatmap, blueteam_baseline_profile, blueteam_baseline_drift
   (current vs baseline Z-score anomaly).
3. CORRELATION / APT — three_sum_correlation(use_attack_graph=true): campaign-level
   detection with cluster-aware intersection, PPR suspicion boost, confirmed-IOC bonus.
   The LangGraph workflows (group 7) inherit this mode by default.
4. IOC INTELLIGENCE — blueteam_extract_iocs, blueteam_ioc_lifecycle (time-decay ranked
   store), blueteam_stix_killchain (per-srcip ATT&CK chain), blueteam_stix_analyze.
5. GRAPH ENGINEERING — blueteam_attack_graph (campaign clusters, hub/bridge IOCs,
   suspicion-ranked unconfirmed IOCs, shortest paths), blueteam_campaign_watch (cluster growth).
6. THREAT INTEL — crowdsec_ip_reputation(_bulk), threatfox_ioc_search(_bulk),
   greynoise_ip_context, blueteam_lookup_ip_abuseipdb, blueteam_lookup_hash_virustotal,
   blueteam_lookup_domain_virustotal, argus_ip_lookup, netra_ip_analysis,
   sangfor_blocklist_check/list, blueteam_unified_threat_score.
7. LANGGRAPH WORKFLOWS — blueteam_investigation_workflow (extract→enrich→correlate→
   graph→killchain→baseline→report/verdict), blueteam_playbook_run (alert-driven
   template hunt + investigation, retries with fallback template). Both default
   use_attack_graph=true — cluster-aware Engine A with PPR + confirmed bonuses.
8. HOST FORENSICS — blueteam_read_auth_log/syslog/web_log, blueteam_journalctl,
   blueteam_list_processes/connections/listening_ports/users/cron_jobs,
   blueteam_hash_file, blueteam_capture_traffic, blueteam_find_suid_files,
   blueteam_failed_logins, blueteam_rootkit_scan, blueteam_lynis_audit,
   blueteam_check_ssh_authorized_keys, blueteam_check_updates + hardening checks.
9. SEARCH & QUERY — blueteam_semantic_search (BM25 over rules/alerts),
   blueteam_whois_lookup, blueteam_crtsh_lookup, blueteam_compromised_emails_analysis.
10. REPORTS & OPERATIONS — blueteam_export_report (docx/xlsx/pptx via officecli),
    blueteam_mark_investigated (verdicts), blueteam_investigation_history/summary,
    blueteam_false_positive_tracker, blueteam_fail2ban_status/jail_status,
    metrics://prometheus resource.

## Standard workflows

- Triage an alert: blueteam_wazuh_alert_summarize → blueteam_extract_iocs →
  crowdsec_ip_reputation / threatfox_ioc_search → blueteam_threat_card.
- Investigate an IP: blueteam_investigate_ip → blueteam_stix_killchain →
  blueteam_attack_graph → (optional) blueteam_mark_investigated with a verdict.
- Full auto-pipeline: blueteam_investigation_workflow (or blueteam_playbook_run for
  alert-driven hunting).
- Hunt a technique: blueteam_threat_hunt (11 templates) → blueteam_attack_graph.
- Detect APT: three_sum_correlation(use_attack_graph=true) → blueteam_campaign_watch →
  blueteam_baseline_drift.

## Schema discipline (anti-hallucination)

- READ each tool's input schema (exposed via the MCP protocol) BEFORE calling — never
  invent parameter names.
- three_sum_correlation uses time_window_minutes (not since/until) for the window.
- Host-forensics log tools (blueteam_read_*_log, blueteam_journalctl) return plain text
  and do not accept response_format.
- When a call is rejected with extra_forbidden, drop the extra parameter and re-read the
  tool's schema instead of retrying the same arguments.

## Privacy rules

- Default redaction is shape-based; under BLUETEAM_REDACTION_POLICY=protect_victim,
  victim emails/subdomains/IPs are masked and attacker IOCs stay visible.
- NEVER call bypass_redaction=True or redaction_policy="raw" unless the operator
  explicitly requests forensic output — hard-gated behind BLUETEAM_ALLOW_FORENSIC_BYPASS
  AND, when BLUETEAM_FORENSIC_TOKEN is set, it also requires forensic_token=<token>
  (which only the operator holds).
- For forensic sessions that must see official emails/subdomains, prefer
  redaction_policy="protect_victim" with reveal_owned=true — other masking stays on.
- Layer 1 (credentials) is never bypassable, including inside attacker payloads.
```

Deployment tip: run the MCP server with
`BLUETEAM_REDACTION_POLICY=protect_victim BLUETEAM_OWNED_DOMAINS=<your-domain>` and paste the
prompt block above into the LLM client's system prompt.


## Contoh Prompt SOC — Laporan Serangan 24 Jam (Bahasa Indonesia)

Prompt teroptimasi berikut memetakan setiap permintaan ke tool MCP yang konkret. Salin ke LLM
lokal yang terhubung ke server ini. Redaction policy: `protect_victim` — email/subdomain dinas
di-mask, attacker IOCs tetap terlihat.

```markdown
# SOC Investigation — 24-Hour Cyber Attack Report for Tangerang Kota Infrastructure

**Redaction policy for this session:** `protect_victim` (victim emails/subdomains masked,
attacker IOCs visible). **DO NOT use bypass_redaction.** Internal emails and subdomains
will be exported unmasked in the final report only.

---

## Phase 1 — Data Collection (jalankan berurutan, gunakan cursor untuk pagination)

### 1a. Ambil seluruh alert 24 jam terakhir
Gunakan `blueteam_wazuh_indexer_search` dengan `since="24h"`, `max_scanned=10000`.
Iterasi dengan `next_cursor` hingga `has_more=false`. Simpan seluruh hasil.

### 1b. Subdomain Kota Tangerang yang paling banyak diserang
Gunakan `blueteam_wazuh_geo_distribution` dengan `since="24h"` untuk melihat sebaran
serangan per domain/subdomain. Urutkan dari yang paling banyak diserang. Untuk setiap
subdomain, gunakan `blueteam_wazuh_domain_lookup` untuk mendapatkan detail IP attacker
dan payload.

### 1c. Email dinas yang locked
Gunakan `blueteam_wazuh_compromised_emails_analysis` dengan `since="24h"`.
Filter untuk event dengan status `is locked`.

### 1d. IP publik dengan authentication success
Gunakan `blueteam_wazuh_indexer_search` dengan keyword `"authentication success"`
atau `"Accepted"`, `since="24h"`. Ekstrak seluruh IP publik dari hasil.

---

## Phase 2 — Threat Intelligence Enrichment (per IP attacker dari Phase 1)

### 2a. ThreatFox lookup
Gunakan `threatfox_ioc_search` (atau `threatfox_ioc_search_bulk` untuk batch 25 IP).

### 2b. Argus lookup
Gunakan `blueteam_lookup_argus` untuk setiap IP attacker dari Phase 1a dan IP publik
dari Phase 1d.

### 2c. CrowdSec lookup
Gunakan `crowdsec_ip_reputation_bulk` untuk batch IP attacker.

### 2d. AbuseIPDB lookup
Gunakan `blueteam_lookup_ip_abuseipdb` untuk IP dengan confidence rendah.

### 2e. MITRE ATT&CK mapping
Gunakan `blueteam_mitre_lookup` untuk setiap teknik MITRE dari hasil CrowdSec/ThreatFox.

---

## Phase 3 — Correlation & Scoring

### 3a. 3-Sum APT detection
Gunakan `three_sum_correlation` dengan `time_window_minutes=1440` (24 jam),
`threshold_score=10`, `z_score_threshold=2.5`. Periksa apakah ada IP yang muncul
di ketiga kategori (recon, access, exfil) — indikasi APT group.

### 3b. BM25 semantic search
Gunakan `blueteam_semantic_search` dengan `source="alerts"`, `since="24h"`,
`top_k=20`. Query: `"serangan siber tangerangkota csirt"`.

### 3c. Unified threat scoring
Gunakan `blueteam_unified_threat_score` untuk menggabungkan hasil ThreatFox +
CrowdSec + AbuseIPDB menjadi single confidence score per IP.

---


## Phase 4 — Report & Export

### 4a. Geo heatmap
Gunakan `blueteam_wazuh_geo_heatmap` dengan `since="24h"`.

### 4b. Generate markdown report (MASKED — untuk presentasi dan chat output)
Susun laporan awal dengan data dari Phase 1-3. Pada tahap ini, email/subdomain dinas
masih dalam keadaan ter-mask (`protect_victim`, tanpa `reveal_owned`). Laporkan:
1. Ringkasan eksekutif (total serangan, top 5 IP attacker, top 3 subdomain diserang)
2. Subdomain terbanyak diserang + IP attacker + payload per subdomain
3. Email locked + analisis Argus/ThreatFox per IP penyebab
4. Hasil 3-Sum APT correlation (flags jika ada IP multi-kategori)
5. BM25 ranked results
6. MITRE ATT&CK techniques terdeteksi
7. Geo heatmap summary

### 4c. Re-run data collection dengan `reveal_owned=true` (FORENSIK — untuk laporan akhir saja)

**KHUSUS untuk laporan akhir yang akan disimpan ke file**, jalankan ulang query berikut
dengan parameter `reveal_owned=true` agar email dinas dan subdomain tangerang kota
terlihat asli (unmasked). **JANGAN gunakan `bypass_redaction`.**

```text
blueteam_wazuh_indexer_search(
    since="24h",
    max_scanned=10000,
    redaction_policy="protect_victim",
    reveal_owned=true
)

blueteam_wazuh_compromised_emails_analysis(
    since="24h",
    redaction_policy="protect_victim",
    reveal_owned=true
)

blueteam_wazuh_domain_lookup(
    domain="<subdomain dari Phase 1b>",
    redaction_policy="protect_victim",
    reveal_owned=true
)
```
```markdown
### 4d. Generate laporan akhir (UNMASKED — hanya untuk file)

Gunakan hasil dari 4c untuk menyusun laporan akhir yang **menampilkan email dinas
dan subdomain tangerang kota secara lengkap**. Kemudian export:

- Gunakan `blueteam_wazuh_export` untuk menyimpan hasil ke JSONL, atau format manual ke `.md`.
- Untuk laporan Office: gunakan `blueteam_export_report` (docx/xlsx/pptx).
```

**PENTING — Chain of custody:**
- Output chat dan layar HANYA menampilkan laporan masked (hasil 4b).
- Data unmasked (hasil 4c) HANYA disimpan ke file — jangan ditampilkan di chat.
- Laporan akhir di file (.md/.docx) berisi data forensik lengkap dengan email/subdomain dinas asli.
```

### Cara Kerja Chain `reveal_owned=true`

```
Phase 1-3 (TRIAGE — data yang diproses dan di-reasoning LLM):
  protect_victim, TANPA reveal_owned
  → a***i@tangerangkota.go.id [h:abc123]   ← MASKED
  → mail.tangerangkota.go.id                ← MASKED
  → 45.33.32.156                            ← UNMASKED (attacker)

Phase 4c (FORENSIK — re-run khusus untuk file):
  protect_victim + reveal_owned=true
  → auli@tangerangkota.go.id                ← UNMASKED
  → mail.tangerangkota.go.id                ← UNMASKED
  → 45.33.32.156                            ← UNMASKED (attacker)

Phase 4d (EXPORT):
  File (.md/.docx) ← berisi data unmasked lengkap
  Chat output      ← tetap masked (hasil Phase 4b)
```

LLM **tidak pernah melihat** data unmasked selama reasoning dan triage. Data unmasked
hanya diproses pada Phase 4c untuk penulisan file akhir.

### Catatan Penggunaan

- **Redaction**: prompt di atas menggunakan `protect_victim` — email/subdomain dinas
  di-mask selama triase, hanya dibuka (`reveal_owned=true`) pada laporan akhir jika
  diperlukan untuk forensik.
- **JANGAN gunakan `bypass_redaction=true`** — itu membuka seluruh masking (raw mode)
  dan memerlukan forensic token (yang hanya dipegang operator).
- Untuk sesi forensik yang harus melihat email/subdomain dinas asli, gunakan
  `redaction_policy="protect_victim"` dengan `reveal_owned=true` — masking lainnya
  tetap aktif.
- **Layer 1 (credential stripping) tidak pernah bisa di-bypass**, termasuk di dalam
  attacker payload.

Deployment tip: jalankan server dengan
`BLUETEAM_REDACTION_POLICY=protect_victim BLUETEAM_OWNED_DOMAINS=tangerangkota.go.id`
dan paste prompt block di atas ke system prompt LLM client.

## Requirements

**Defender Host:**
- Ubuntu 20.04+ or Debian 11+ (other distros work with minor adjustments)
- Python 3.11+ (required for modern type hints and Pydantic v2)
- OpenSSH server

**Optional system tools** (setup.sh installs these):
- `tcpdump`, `fail2ban`, `lynis`, `rkhunter`, `chkrootkit`

**Python packages** (auto-installed in venv):
- `mcp>=1.0.0,<2.0.0`
- `httpx>=0.27.0,<0.28.0`
- `pydantic>=2.0.0,<3.0.0`\n- `networkx>=3.0,<4.0`\n- `langgraph>=0.2,<0.6`

**Server files:**

| File | Role |
|---|---|
| `main.py` + `mcp_server/` | **Primary** — all 97 tools, both transports (stdio / Streamable HTTP) |

### Legacy Naming Debt

Five Wazuh tools use the prefix `wazuh_` without the `blueteam_` namespace
qualifier, while the other Wazuh tools use `blueteam_wazuh_`:

| Current Name | Preferred (Future) | Status |
|---|---|---|
| `wazuh_email_lookup` | `blueteam_wazuh_email_lookup` | Active — do not rename (backward compat) |
| `wazuh_domain_lookup` | `blueteam_wazuh_domain_lookup` | Active — do not rename (backward compat) |
| `wazuh_compromised_emails_analysis` | `blueteam_wazuh_compromised_emails_analysis` | Active — do not rename (backward compat) |
| `wazuh_alert_timeline` | `blueteam_wazuh_alert_timeline` | Active — do not rename (backward compat) |
| `wazuh_attack_velocity` | `blueteam_wazuh_attack_velocity` | Active — do not rename (backward compat) |
| `wazuh_wazuh_indexer_search` | `blueteam_wazuh_indexer_search` | **Alias** — delegates to `blueteam_wazuh_indexer_search` (both names valid) |

Hard Rule 1, these names are frozen to avoid breaking active
client workflows. A future major version may introduce the `blueteam_wazuh_`
aliases alongside a deprecation window for the short names.

## Development Guardrails

Before deploying, run the automated regression linter:

```bash
python3 check_guardrails.py        # 7 checks: unbound, drift, overaggressive params., order, imports, closures, unexpected kwargs
python3 check_guardrails.py --strict  # CI mode: non-zero exit on any warning
```

## Phase 1-3 Changelog (Aug 2026)

| Feature | Phase | Description |
|---|---|---|
| Typed Config (`core/config.py`) | 1 | 13 nested dataclasses replacing ~60 `os.environ` reads; `validate()` raises on fatal errors |
| Exception Hierarchy (`core/exceptions.py`) | 1 | `BlueTeamMCPError` → `ConfigurationError`, `WazuhAuthError`, `WazuhAPIError`, `ThreatIntelError` |
| JWT 60s Expiry Buffer (`wazuh/auth.py`) | 1 | Instance-scoped `WazuhAuthManager` with proactive token refresh |
| `@blueteam_tool` Decorator (`core/tool_decorator.py`) | 2 | Auto-applies audit logging, exception catching, and response truncation |
| Tool Gating (`tools/__init__.py`) | 2 | `WAZUH_DISABLED_CATEGORIES`, `WAZUH_READ_ONLY` — skip modules before import |
| Agent Filter Parity (`tools/wazuh_siem.py`) | 2 | `status`, `q`, `sort`, `select`, `search`, `distinct` on `blueteam_wazuh_agents` |
| Dynamic Tool Count | 2 | Runtime-derived from FastMCP registry — no more hardcoded "92" |
| SCA Compliance Tools (`tools/wazuh_sca.py`) | 3 | `blueteam_wazuh_get_agent_sca`, `blueteam_wazuh_get_sca_policy_checks`, `blueteam_wazuh_list_sca_policies` |
| Rule-File Tools (`tools/wazuh_rules_files.py`) | 3 | `blueteam_wazuh_get_rule_files`, `blueteam_wazuh_get_rule_file_content` |
| Test Suite (`tests/`) | 3 | 56 tests, 0 failures — exceptions, redact, correlation, auth |
| Config Consolidation (`mcp_server/__init__.py`) | 4 | Module-level vars sourced from `Config` singleton; backward-compatible exports |
| HTTP/2 + Retry Jitter (`core/http_client.py`) | 7 | `http2=True` on all pooled clients; jittered 200-400ms backoff prevents thundering herd |
| Guardrail Pre-Commit Hook (`.git/hooks/pre-commit`) | 8 | `check_guardrails.py --strict` blocks commits with DRIFT/CLOSURE/UNBOUND bugs |
