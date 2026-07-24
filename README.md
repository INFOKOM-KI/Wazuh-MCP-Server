# Blue Team MCP Server (Wazuh SIEM)

A defensive security MCP server for Claude Desktop or any MCP Client - the defender's counterpart to [mcp-kali-server](https://www.kali.org/blog/kali-llm-claude-desktop/).

Where Kali Linux gives Claude offensive tools (nmap, gobuster, sqlmap), this gives Claude **blue team / SOC analyst tools** to investigate, monitor, and harden your systems.

**Programmer** : `NAuliajati` (`csirt[at]tangerangkota[.]go[.]id`)
**Recoded** :  `https://github.com/not2cleverdotme/blue-team-mcp`

---

## Architecture

`main.py` (with the `mcp_server/` package) is a **modular MCP server** with 85 tools spanning host forensics, Wazuh SIEM, threat intelligence, Sangfor blocklist integration, alert enrichment, 3-Sum APT correlation engine, MITRE ATT&CK, threat hunting, domain investigation, and IOC extraction. It supports two transports:

| Transport | Use case | MCP client connection |
|---|---|---|
| `stdio` | Local subprocess or SSH pipe | Direct (Claude Desktop stdio) |
| `streamable_http` | Remote HTTP service | `http://<host>:<port>/mcp` |

```
                          ┌──────────────────────────────────┐
                          │     main.py                     │
                          │     85 tools · modular · 2 transports  │
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
| `main.py` + `mcp_server/` | **All 85 tools** | **Recommended** — full capabilities, credential stripping, PII redaction |

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

Per `SKILLS.md` §3.1, CrowdSec CTI responses are cached in-process with configurable TTL:

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

Restart Claude Desktop. You should see all 50 blue-team-mcp tools available.

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
| `three_sum_correlation` | **3-Sum APT Detection Engine**: Engine A (intersection scoring) + Engine B (volumetric Z-score) + **unified cross-engine scoring**. Auto-scaled bucket intervals, account lockout counter, `follow_up="curated_report"` for auto-enriching trigger IPs. Category B defaults include `spam`/`postfix`. |
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
| `blueteam_wazuh_syscheck` | 🆕 File Integrity Monitoring — track file additions, modifications, deletions |
| `blueteam_wazuh_compliance` | 🆕 Compliance framework summary (CIS, PCI DSS, GDPR, HIPAA, NIST 800-53) |
| `blueteam_wazuh_geo_heatmap` | 🆕 Attack coordinate + city-level geo heatmap for visualization |
| `blueteam_semantic_search` | 🆕 BM25 semantic search — natural language queries against Wazuh rules |

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

## Example Prompts

Once connected via Claude Desktop, you can ask:

```
"Check the last 2 hours of auth.log and tell me if there are any brute force
 attempts. Group by source IP."

"Show me all listening ports. Are any unexpected services running?"

"Here are 5 IPs from my nginx access log: 1.2.3.4, 5.6.7.8, 9.10.11.12,
 13.14.15.16, 200.1.2.3 — look them all up on AbuseIPDB."

"Run a Lynis audit and give me the top 5 highest priority hardening items."

"Check for any SUID binaries that aren't in the standard list of expected ones."

"Who is currently logged into this server, and when did they log in?"

"Scan all user cron jobs and flag anything that looks suspicious."

"Hash /usr/bin/sshd and check it against VirusTotal."

"Check the CrowdSec reputation of 185.220.101.1 — does it have known attack
 behaviors or associated CVEs?"

"Is 71.6.135.131 a known internet scanner? Check with GreyNoise and tell me
 if it's noise I can ignore or something to investigate."

"Triage these 5 IPs from my firewall logs against both GreyNoise and CrowdSec.
 Filter out known scanners and business services, then prioritize the rest
 by reputation."

"Search the Wazuh indexer for all alerts from agent HYDRA-DC in the last 24 hours.
 Use cursor pagination to iterate through all results — don't stop at the first page."

"List every Wazuh agent across the fleet. We have over 1,500 endpoints, so use
 cursor pagination to enumerate them all — then group by OS and status."
```

---

## MAESTRO Framework Alignment (currently for dev only)

This server aligns with the [CSA MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) framework for agentic AI security. See [MAESTRO.md](MAESTRO.md) for the threat model and mitigations.

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
- `pydantic>=2.0.0,<3.0.0`

**Server files:**

| File | Role |
|---|---|
| `main.py` + `mcp_server/` | **Primary** — all 85 tools, both transports (stdio / Streamable HTTP) |

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

Per CLAUDE.md Hard Rule 1, these names are frozen to avoid breaking active
client workflows. A future major version may introduce the `blueteam_wazuh_`
aliases alongside a deprecation window for the short names.

## Development Guardrails

Before deploying, run the automated regression linter:

```bash
python3 check_guardrails.py        # 6 checks: unbound locals, params. misuse, import order, closures, drift, overaggressive
python3 check_guardrails.py --strict  # CI mode: non-zero exit on any warning
```

See `CLAUDE.md` §5 for the full pre-merge checklist.
