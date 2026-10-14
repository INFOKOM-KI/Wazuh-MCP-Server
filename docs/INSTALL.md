# Installing and Configuring Wazuh MCP Server on Linux

This guide explains how to install **INFOKOM-KI Wazuh MCP Server** on Ubuntu/Debian, configure `config.env`, run it with `systemd`, and test connectivity. The instructions follow `setup.sh`, the configuration, and the `README` in the repository as reviewed when this document was prepared. Because the `main` branch can change, review the scripts again before running them on a production server.

- Repository: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server>
- Installer: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/setup.sh>
- README/configuration overview: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/README.md>
- Entry point: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/main.py>

> **Important:** `WAZUH_INDEXER_URL` and `WAZUH_INDEXER_PASSWORD` must be set for the Indexer configuration to be valid. The Wazuh Manager API is optional. `setup.sh` creates `config.env` with many examples commented out; lines beginning with `#` are inactive. Enable only the options you need, and retain the default security settings wherever possible.

## 1. Choose the architecture and transport mode

| Mode | When to choose it | Recommendation |
|---|---|---|
| `stdio` | The MCP client runs locally or connects to the server over SSH and uses stdin/stdout | Simplest option; no need to expose an MCP HTTP port. Suitable for Claude Desktop over SSH. |
| `streamable_http` | The server runs as a persistent service and clients connect through an HTTP endpoint | Use `systemd`, an API key, a restricted firewall, and TLS through a reverse proxy/VPN for network access. |

The examples below use **Streamable HTTP bound only to `127.0.0.1:8000`**, with the service running as a non-root system user. A reverse proxy or VPN can be used when the client runs on another machine. If you only need SSH/stdio, see Section 12.

## 2. Prerequisites

Prepare the following:

- Ubuntu/Debian with Python **3.11 or newer**.
- `sudo` privileges and internet access to retrieve the repository/packages during installation.
- Connectivity from the MCP Server to the Wazuh Indexer (usually TCP port `9200`).
- Indexer account credentials that comply with your organization's policies. If available, create a service account with the minimum permissions needed to read the required indices/alerts.
- Wazuh Manager API (usually TCP port `55000`) for features that manage or read Manager data, agents, rules, and configuration.
- Disk space for the virtual environment, logs, SQLite/JSONL state, and caches. Unless disabled, the default installation downloads a reranker model of approximately 1 GB.

Check the OS and Python version:

```bash
cat /etc/os-release
python3 --version
```

If Python is older than 3.11, do not continue with that interpreter. The easiest option is to use an Ubuntu/Debian release that provides Python 3.11+ from a supported OS repository. Avoid forcibly replacing the system's `/usr/bin/python3`.

## 3. Install system packages and clone the repository

```bash
sudo apt-get update
sudo apt-get install -y git curl ca-certificates python3 python3-pip python3-venv

git clone https://github.com/INFOKOM-KI/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

git status --short
git rev-parse --short HEAD
```

Record the installed commit to make auditing and rollback easier. Before running the installer, review `setup.sh`, especially on a production server. The installer uses `apt-get` and attempts to install `tcpdump`, `fail2ban`, `rkhunter`, `chkrootkit`, `lynis`, `net-tools`, `iproute2`, `procps`, and `openssh-server`. It also attempts to enable the SSH service and grant packet-capture capabilities to `tcpdump`. Check whether these actions comply with your host-hardening policies.

## 4. Create a service account before installation

`setup.sh` does not automatically create a service account. For `systemd` mode, create a dedicated account without interactive login:

```bash
getent passwd blueteam-mcp >/dev/null || \
  sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin blueteam-mcp

id blueteam-mcp
```

Do not run the server as `root` unless necessary. This account will be used by the `systemd` unit, while the source code and virtual environment remain managed by `root`.

Create locations for state/logs/exports used by the example configuration:

```bash
sudo install -d -o blueteam-mcp -g blueteam-mcp -m 0750 /var/log/blue-team-mcp
sudo install -d -o blueteam-mcp -g blueteam-mcp -m 0750 /var/log/blue-team-mcp/exports
```

If the `blueteam-mcp` account already exists, do not create a duplicate account. Also check whether state directories from an existing installation contain data that must be preserved.

## 5. Run `setup.sh`

### 5.1 Standard installation

Run the script from the repository root containing `setup.sh`, `main.py`, `requirements.txt`, and the `mcp_server/` directory:

```bash
sudo bash setup.sh
```

The script generally does the following:

1. Installs the OS packages listed in Section 3.
2. Copies `main.py`, `mcp_server/`, and `requirements.txt` to `/opt/blue-team-mcp`.
3. Creates a virtual environment at `/opt/blue-team-mcp/venv` and installs Python dependencies.
4. Attempts to run `pip-audit` if it can be installed.
5. Sets up the reranker model unless disabled.
6. Creates `/opt/blue-team-mcp/config.env` if the file does not already exist.
7. Synchronizes a number of model variables to `config.env` and `/opt/blue-team-mcp/.env`.
8. Creates the `/usr/local/bin/mcp-server-blueteam` wrapper and a legacy compatibility wrapper.
9. Attempts to enable SSH and grant capabilities to `tcpdump`.

**The installer does not overwrite an existing `config.env`.** During updates, review the script output to see which files were preserved, and review new configuration options that may have been added in the source-code version.

### 5.2 Choose whether to download the reranker model

Reranking is enabled by default, and the installer attempts to download `BAAI/bge-reranker-base` (approximately 1 GB) to the local cache. The model is intended to run offline afterward. If the host has limited bandwidth/disk space or you want to start with lexical search only, run the installation below instead of the standard installation command:

```bash
sudo env BLUETEAM_RERANK_ENABLED=false bash setup.sh
```

With this option, the server does not bootstrap the default model, and search can still use lexical/BM25 ranking along the supported path. Do not set `BLUETEAM_RERANK_ENABLED=true` again until a compatible model is available and has passed validation. The model name must be supported by the `fastembed` cross-encoder registry or registered as a custom model according to the project implementation.

### 5.3 Installation features are opt-in

Do not enable optional packages or models unless needed. Select them when running the installer, for example:

```bash
# Example: convert Office documents/digital PDFs to Markdown, without downloading an OCR model
sudo env BLUETEAM_INSTALL_MARKITDOWN=1 bash setup.sh

# Example: Sigma conversion support with pySigma/OpenSearch backend
sudo env BLUETEAM_INSTALL_SIGMA=1 bash setup.sh

# Example: alert clustering using HDBSCAN/scikit-learn
sudo env BLUETEAM_INSTALL_CLUSTER=1 bash setup.sh

# Example: HMM forecast (additional dependencies)
sudo env BLUETEAM_INSTALL_FORECAST=1 bash setup.sh
```

Optional flags available in `setup.sh` include:

| Flag | Effect | Notes |
|---|---|---|
| `BLUETEAM_INSTALL_MARKITDOWN=1` | Installs conversion of local documents/datasets to Markdown | Does not require an OCR model; scanned/image-only files still require an OCR path. |
| `BLUETEAM_INSTALL_MARKER=1` | Installs Marker for PDF/document conversion | Heavy. Installs pinned CPU PyTorch/torchvision versions. OCR for scanned pages requires the `llama-server` binary from llama.cpp and an additional OCR model. |
| `BLUETEAM_PREWARM_MARKER=1` | Requests Marker model prewarming through the installer path | Enable only after approving the large Surya model download and its disk/bandwidth requirements. |
| `BLUETEAM_INSTALL_SIGMA=1` | Installs pySigma and the OpenSearch backend | Required for Sigma conversion functions; basic authoring/validation may be available without the conversion backend. |
| `BLUETEAM_INSTALL_CLUSTER=1` | Installs dependencies for clustering/HDBSCAN | After installation, clustering must still be enabled with `BLUETEAM_CLUSTER_ENABLED=true`. |
| `BLUETEAM_INSTALL_FORECAST=1` | Installs additional HMM/forecast dependencies | Forecasting remains disabled until `BLUETEAM_FORECAST_ENABLED=true`. |
| `BLUETEAM_INSTALL_LAYA=1` | Installs the Laya backend stack | Requires an already-provided/pinned model; it does not automatically download model weights when the tool is called. |
| `BLUETEAM_INSTALL_SETFIT=1` | Installs SetFit and CPU PyTorch | Requires validated model artifacts and the correct path/hash. |

If several features are required for the initial installation, combine their flags in one `sudo env ... bash setup.sh` invocation. If `config.env` does not yet exist, pass installation flags through the environment as shown above; the installer cannot read them from a file that has not been created yet.

## 6. `config.env` configuration: location, format, and permissions

The main runtime configuration file is:

```text
/opt/blue-team-mcp/config.env
```

Open it with an editor:

```bash
sudo nano /opt/blue-team-mcp/config.env
```

### 6.1 Correct format

This file is *sourced* by the shell wrapper, so use shell syntax without `export`:

```bash
VARIABLE_NAME="value..."
```

Commented lines are inactive. To change an existing example, remove the leading `#` and replace the value. Empty variable values do not automatically make an integration functional.

Practical rules:

- Use `https://` URLs for services that support TLS.
- There is no need to add a trailing `/` to the MISP URL; Wazuh URLs that end in a slash are normalized for some configurations.
- Boolean values are read as `true`/`false` (many configurations also accept `1`/`yes`); use `true` or `false` consistently.
- Separate multiple category names, tools, domains, IPs, or Origins with commas where specified in the variable comments. Do not guess delimiters. Check the relevant reference below.
- Avoid unescaped quote characters in passwords. Test that the file can be *sourced* before restarting the service.
- Never commit `config.env`, share it in a public issue, or include secrets in logs/screenshots.

Validate the shell syntax without displaying secrets:

```bash
sudo bash -n /opt/blue-team-mcp/config.env
```

This command checks shell syntax; it does not validate whether credentials or configuration values are correct.

### 6.2 File permissions (must be tightened)

`setup.sh` creates the initial file with permissions that are not sufficiently restrictive for a file that will contain secrets. After adding credentials, set the ownership and mode correctly:

```bash
sudo chown root:blueteam-mcp /opt/blue-team-mcp/config.env
sudo chmod 640 /opt/blue-team-mcp/config.env
sudo chown root:root /opt/blue-team-mcp
sudo chmod 755 /opt/blue-team-mcp
```

Mode `640` means only `root` and members of the `blueteam-mcp` group can read the configuration. The `systemd` account must belong to that group (the user/group settings in the unit in Section 9 ensure the effective group is used). Do not use `chmod 644` for a file containing passwords/API keys. Since the directory and virtual environment are managed by root, the service user must not be able to modify the source code.

## 7. Minimum required configuration

### 7.1 Wazuh Indexer (required)

The Indexer/OpenSearch is the primary source of alert/event data. For a normal installation, set at least the following variables:

```bash
export WAZUH_INDEXER_URL="https://wazuh-indexer.example.internal:9200"
export WAZUH_INDEXER_USER="<indexer_readonly_user>"
export WAZUH_INDEXER_PASSWORD="<indexer_password>"
export WAZUH_INDEXER_VERIFY_SSL="true"
export WAZUH_INDEXER_MAX_SIZE="10000"
```

Replace the host, username, and password. `WAZUH_INDEXER_MAX_SIZE` sets the page size limit for search results; a large value can increase memory usage and response size.

| Variable | Required? | Meaning |
|---|---|---|
| `WAZUH_INDEXER_URL` | **Yes** | Base Indexer URL, usually `https://HOST:9200`. |
| `WAZUH_INDEXER_USER` | Required for authentication | The setup default is `admin`; when available, use a dedicated account with minimum required permissions. |
| `WAZUH_INDEXER_PASSWORD` | **Yes** | Indexer account password. Startup validation fails if it is empty. |
| `WAZUH_INDEXER_VERIFY_SSL` | Strongly recommended: `true` | Validates the Indexer server certificate. |
| `WAZUH_INDEXER_MAX_SIZE` | Optional | Maximum number of documents per search page; default is `10000`. |
| `BLUETEAM_INDEXER_CACHE_TTL` | Optional | Indexer aggregation cache/deduplication interval in seconds; default is `30`; `0` disables the cache. |

### 7.2 Wazuh Manager API

The Manager API is used by tools that interact with Manager endpoints, such as agent data, rules, and configuration. Set these variables only if the address and credentials are available:

```bash
export WAZUH_API_URL="https://wazuh-manager.example.internal:55000"
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="<manager_api_password>"
export WAZUH_API_VERIFY_SSL="true"
```

| Variable | Meaning |
|---|---|
| `WAZUH_API_URL` | Manager API URL. If empty, the Manager API is not configured. |
| `WAZUH_API_USER` | Default is `wazuh-wui`; use an appropriate account and do not assume the default user fits every installation. |
| `WAZUH_API_PASSWORD` | Required if `WAZUH_API_URL` is set. |
| `WAZUH_API_VERIFY_SSL` | Default is `true`; disable it only for lab testing that genuinely uses a self-signed certificate, not as a permanent solution. |

Do not confuse the Indexer password with the Manager API password; they belong to separate services and authentication systems.

### 7.3 TLS/CA

Keep `WAZUH_INDEXER_VERIFY_SSL=true` and `WAZUH_API_VERIFY_SSL=true`. If the certificate is signed by an internal CA, install the correct root/intermediate certificate in the OS trust store and run `sudo update-ca-certificates` (on distributions that use this command). Disabling TLS verification can make the connection vulnerable to man-in-the-middle attacks.

Test DNS/routing/port connectivity without exposing secrets:

```bash
getent hosts wazuh-indexer.example.internal
curl -I --max-time 5 https://wazuh-indexer.example.internal:9200/
```

A `401` response from the endpoint can mean the server is reachable but authentication has not been provided. This is different from a DNS or TLS failure. Do not send credentials to an untrusted URL.

## 8. Runtime security configuration and MCP HTTP

### 8.1 Production baseline

Use the following baseline in `config.env`, adjusting `MCP_API_KEY` if using HTTP:

```bash
# Local HTTP mode; the systemd service in Section 9 also sets the CLI transport/host/port
export MCP_TRANSPORT="streamable_http"
export MCP_HOST="127.0.0.1"
export MCP_PORT="8000"

# Set this to a generated token; do not use this placeholder literally
export MCP_API_KEY="btm_REPLACE_WITH_A_REAL_TOKEN"
export MCP_API_KEY_SCOPES="wazuh:read"

# Reduce the risk from tools that can change state or the host during initial deployment
export WAZUH_READ_ONLY="true"
export WAZUH_DISABLED_CATEGORIES=""
export WAZUH_DISABLED_TOOLS=""

# Inbound HTTP hardening (optional)
export BLUETEAM_HTTP_RATE_LIMIT="60"
export BLUETEAM_ALLOWED_ORIGINS=""

# Logging
export LOG_LEVEL="INFO"
export BLUE_TEAM_MCP_SERVER_NAME="blue_team_mcp"
```

Generate a random token:

```bash
python3 -c 'import secrets; print("btm_" + secrets.token_urlsafe(32))'
```

Copy the result into `MCP_API_KEY` in the configuration file. Do not store the token only in shell history or put it in a URL query string.

| Variable | Value/meaning |
|---|---|
| `MCP_TRANSPORT` | `stdio` or `streamable_http`; default is `stdio`. |
| `MCP_HOST` | Default is `127.0.0.1`. Binding to a non-loopback address requires `MCP_API_KEY`; the program refuses to start if the key is missing. |
| `MCP_PORT` | Default is `8000`; choose an available port. |
| `MCP_API_KEY` | Pre-shared key for authenticating HTTP clients. When set, authentication applies to all HTTP requests, including loopback requests. |
| `MCP_API_KEY_SCOPES` | Default is `wazuh:read`. An example write-capable scope is `wazuh:read wazuh:write`; use it only if necessary and approved. |
| `BLUETEAM_HTTP_RATE_LIMIT` | HTTP request limit per minute per client IP; example: `60`. `0` disables this limit. |
| `BLUETEAM_ALLOWED_ORIGINS` | Exact allowed Origin values, separated by commas. Loopback is always allowed. Set this only to Origins actually used by browser clients; it is not the MCP endpoint URL. |
| `WAZUH_READ_ONLY` | Reduces the set of registered tools, including host-forensics/Fail2ban categories in the current implementation. Set it explicitly: the installer wrapper currently falls back to `false` if the variable is unset. This is not a substitute for the HTTP `wazuh:read` scope or least-privilege permissions on the Wazuh account. |
| `WAZUH_DISABLED_CATEGORIES` | Tool categories to disable, separated by commas. Use category names recognized by the repository version. |
| `WAZUH_DISABLED_TOOLS` | Specific tool names that must not be registered, separated by commas. |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, or `ERROR`; use `INFO` normally and `DEBUG` only during investigations. |
| `BLUE_TEAM_MCP_SERVER_NAME` | Name displayed by the MCP server; use lowercase to avoid casing differences. Default is `blue_team_mcp`. |

> Do not bind the server to `0.0.0.0` merely to make it accessible to remote clients. A safer option is to keep loopback binding and provide HTTPS through a reverse proxy or VPN. If direct binding is necessary, use a specific private IP, require an API key, restrict the firewall to client IPs, and do not expose the port to the internet.

### 8.2 Read-only mode and tool permissions

For an initial SOC deployment, explicitly set:

```bash
export WAZUH_READ_ONLY="true"
export MCP_API_KEY_SCOPES="wazuh:read"
```

The number of active tools varies with the repository version and gating. The tool count does not prove that the Indexer/Manager API integration is working. Over HTTP, the `wazuh:read` scope is a per-request access control that is separate from tool registration. Do not assume HTTP scopes apply to stdio. If a workflow genuinely requires write operations, first evaluate the specific tool, Wazuh account permissions, audit trail, operator approval, and potential impact. Do not enable all permissions merely to eliminate an error.

### 8.3 Input limits, responses, timeouts, and filesystem access

```bash
export BLUETEAM_CHARACTER_LIMIT="100000"
export BLUETEAM_MAX_INPUT_FILE_MB="1024"
export HTTP_TIMEOUT="30"
export BLUETEAM_RATE_LIMIT="0"
export BLUETEAM_ALLOWED_PATHS="/var:/etc:/home:/opt:/usr"
export BLUETEAM_CAPTURE_DIR="/tmp"
```

- `BLUETEAM_CHARACTER_LIMIT`: maximum number of characters in a tool response before truncation; this is not the input-file size limit.
- `BLUETEAM_MAX_INPUT_FILE_MB`: maximum document file size processed; the default `1024` means 1 GB. Increase it only after evaluating the need and host memory.
- `HTTP_TIMEOUT`: general timeout per upstream request in seconds; default is `30`. Some providers may use longer provider-specific timeouts.
- `BLUETEAM_RATE_LIMIT`: global per-minute limit for certain destructive tools (for example, Fail2ban unban and `tcpdump` capture); default `0` means this additional limit is disabled. It is different from `BLUETEAM_HTTP_RATE_LIMIT`, which limits HTTP requests per client IP.
- `BLUETEAM_ALLOWED_PATHS`: allowed path prefixes, separated by colons (`:`), not commas.
- `BLUETEAM_CAPTURE_DIR`: capture output directory; default is `/tmp`. Restrict access to capture results because they may contain sensitive data.

### 8.4 PII redaction and forensic features

Keep the following redaction and forensic gates for the baseline:

```bash
export BLUETEAM_REDACT_PII="true"
export BLUETEAM_REDACT_EMAILS="true"
export BLUETEAM_REDACT_DOMAINS="true"
export BLUETEAM_REDACT_LOCATIONS="true"
export BLUETEAM_REDACTION_POLICY="protect_victim"
export BLUETEAM_REDACT_SALT="REPLACE_WITH_A_RANDOM_VALUE_PER_DEPLOYMENT"

# Adjust to your organization's domains; do not retain example/project domains if irrelevant
export BLUETEAM_OWNED_DOMAINS="example.go.id"
export ALLOWED_INTERNAL_DOMAINS=""
export BLUETEAM_ALLOW_FORENSIC_BYPASS="false"
export BLUETEAM_ALLOW_IDENTITY_REVEAL="false"
export BLUETEAM_ALLOW_RUNTIME_DOMAINS="false"
export BLUETEAM_ALLOW_UNTRUNCATED="false"
```

| Variable | Description |
|---|---|
| `BLUETEAM_REDACT_PII` | Enables the redaction pipeline. Keep it `true` unless a change has been approved and tested. |
| `BLUETEAM_REDACT_EMAILS`, `BLUETEAM_REDACT_DOMAINS`, `BLUETEAM_REDACT_LOCATIONS` | Redaction controls for the associated data types. Default is `true`. |
| `BLUETEAM_REDACTION_POLICY` | The installer wrapper defaults this to `protect_victim` (the code default is `full`). `protect_victim` masks victim-owned indicators while preserving attacker IOCs, and the server falls back to `full` if `BLUETEAM_OWNED_DOMAINS` is empty. `full` is more conservative; `raw` is only for forensic scenarios that pass the `BLUETEAM_ALLOW_FORENSIC_BYPASS=true` and `BLUETEAM_FORENSIC_TOKEN` gates. Do not use `raw` for normal operations. |
| `BLUETEAM_OWNED_DOMAINS` | Organization-owned domains, used in redaction/forensic/STIX context. The script's default is tailored to the original project deployment and must be reviewed/replaced. Separate domains with commas. |
| `ALLOWED_INTERNAL_DOMAINS` | Allowlist of internal domains permitted by webshell checks to access non-public addresses. Empty is safer by default; add only domains you own or are authorized to test. |
| `BLUETEAM_REDACT_SALT` | Deployment-specific salt used to hash certain email/path fields. Replace the example with a unique random value; do not reuse the placeholder. |
| `BLUETEAM_ALLOW_FORENSIC_BYPASS` | Allows raw/unmasked forensic bypass in certain paths. Keep `false` unless a specific procedure and approval exist. |
| `BLUETEAM_FORENSIC_TOKEN` | Additional secret for forensic/identity-reveal features; protect it as a credential. Never use an example value. |
| `BLUETEAM_ALLOW_IDENTITY_REVEAL` | Allows identity fields to be revealed when requested by a relevant tool; default is `false`. |
| `BLUETEAM_ALLOW_RUNTIME_DOMAINS` | Allows runtime changes to owned domains; default is `false`. |
| `BLUETEAM_ALLOW_UNTRUNCATED` | Allows untruncated forensic mode for supported workflows; default is `false`. |

Do not enable identity bypass, raw export, or untruncated responses on a shared server for convenience. Review operator access, storage, retention, and auditing before changing these gates.

## 9. Run as a `systemd` service

The following example uses HTTP bound to loopback. Make sure `MCP_API_KEY` is set in `config.env`, then prepare the state directories and permissions:

```bash
sudo install -d -o blueteam-mcp -g blueteam-mcp -m 0750 /var/log/blue-team-mcp /var/log/blue-team-mcp/exports
sudo chown root:blueteam-mcp /opt/blue-team-mcp/config.env
sudo chmod 640 /opt/blue-team-mcp/config.env
```

Create the unit file:

```bash
sudo nano /etc/systemd/system/blue-team-mcp.service
```

Add the following:

```ini
[Unit]
Description=Blue Team Wazuh MCP Server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=blueteam-mcp
Group=blueteam-mcp
WorkingDirectory=/opt/blue-team-mcp
ExecStart=/usr/local/bin/mcp-server-blueteam --transport streamable_http --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/blue-team-mcp
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

`ExecStart` passes the transport, host, and port arguments to `main.py` through the wrapper. Wazuh variables, the API key, redaction options, and other settings are read from `config.env` by the wrapper. If you enable a database or state stored outside `/var/log/blue-team-mcp`, create the directory with minimum necessary permissions and add that path to `ReadWritePaths`. Do not grant runtime write access to the application code or virtual environment.

Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now blue-team-mcp
sudo systemctl status blue-team-mcp --no-pager
```

View the logs:

```bash
sudo journalctl -u blue-team-mcp -n 100 --no-pager
sudo journalctl -u blue-team-mcp -f
```

Make sure the listener is bound only to loopback:

```bash
sudo ss -lntp | grep ':8000'
```

The expected result is `127.0.0.1:8000`, not `0.0.0.0:8000`. If there is a permission error when reading `config.env`, make sure the service uses the `blueteam-mcp` group and that the file is owned by `root:blueteam-mcp` with mode `640`.

## 10. Test the endpoint and authentication

With the example above, the MCP endpoint is `http://127.0.0.1:8000/mcp`. If `MCP_API_KEY` is set, every HTTP request, including loopback requests, must send a bearer token. Test the handshake:

```bash
read -rsp 'MCP API key: ' MCP_API_KEY; echo
curl -i -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer ${MCP_API_KEY}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"linux-smoke-test","version":"1.0"}}}'
unset MCP_API_KEY
```

The handshake tests only the transport and authentication. It does not prove that the Wazuh Indexer or Manager API can be used successfully. After the handshake succeeds, call a read-only MCP tool that reads alerts/indices and verify its results. Do not expose the token in screenshots, debug output, or tickets.

## 11. Access the server from another computer

### Option A: HTTPS reverse proxy or VPN (recommended)

Keep MCP bound to `127.0.0.1:8000`, then terminate TLS at a reverse proxy that supports HTTP streaming and forwards the `Authorization` header. Clients must access the external HTTPS URL on the proxy, not the server's loopback URL. Keep the MCP API key and restrict proxy access through a firewall/VPN.

### Option B: bind to a private interface

If a reverse proxy/VPN is unavailable, use a specific private IP for `MCP_HOST` or `--host`, for example `10.10.10.20`, rather than `0.0.0.0` when that is not necessary. Make sure the key is set. Restrict the firewall to the analyst workstation's IP, for example:

```bash
sudo ufw allow from 10.10.10.50 to 10.10.10.20 port 8000 proto tcp
sudo ufw status verbose
```

Adjust the rule to the UFW syntax supported by your distribution and local firewall policy. Do not open the MCP port to all sources or expose the server directly to the public internet without adequate TLS and access controls.

## 12. Connect an MCP client

### 12.1 Streamable HTTP client

Use the endpoint:

```text
https://mcp.example.go.id/mcp
```

This URL is an example of your reverse proxy, not a universal URL. Configure `Authorization: Bearer <MCP_API_KEY>` through the MCP client's header/secret settings. If the client runs on the same server and there is no reverse proxy, the address can be `http://127.0.0.1:8000/mcp`.

### 12.2 Claude Desktop over SSH/stdio

If the client must launch the server over SSH, the server must run in `stdio` mode. Because the default `MCP_TRANSPORT` is `stdio`, make sure no other configuration forces HTTP. Example Claude Desktop configuration on the analyst's computer:

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "command": "ssh",
      "args": [
        "-i",
        "/home/ANALYST/.ssh/id_ed25519",
        "mcp-user@DEFENDER_HOST",
        "mcp-server-blueteam"
      ]
    }
  }
}
```

Replace the key path, username, and hostname. Install the workstation's public key for the remote account. The SSH account must be able to run `/usr/local/bin/mcp-server-blueteam` and read `/opt/blue-team-mcp/config.env`; because this file contains secrets, do not grant access to an overly broad group. Use a dedicated account and restrict interactive/login access according to server policy. Do not log in as root.

## 13. Optional feature configuration guide

This section covers common groups of settings in `config.env`. **You do not need to configure all of them.** Enable only features whose dependencies are installed, state paths are ready, and functionality and risks have been reviewed.

### 13.1 Threat-intelligence API keys

Each provider is independent. Without a key, some tools remain available, but authenticated provider functionality will be limited. Add only keys you actually have:

```bash
export CROWDSEC_API_KEY="<key>"
export THREATFOX_API_KEY="<key>"
export OTX_API_KEY="<key>"
export URLHAUS_API_KEY="<key>"
export ABUSEIPDB_API_KEY="<key>"
export VIRUSTOTAL_API_KEY="<key>"
export HUDSONROCK_API_KEY="<key>"
export RAPIDAPI_KEY="<key>"
export NVD_API_KEY="<key>"
export GITHUB_TOKEN="<token>"
```

- GreyNoise Community can be used without an API key for supported community tools.
- `NVD_API_KEY` helps increase the NVD CVE-enrichment quota.
- `GITHUB_TOKEN` is optional; it can increase GitHub rate limits and enable search functions that require a token.
- Set `NETRA_API_KEY` and `ARGUS_API_KEY` only if you have authorized access. `ARGUS_BASE_URL` must point to your legitimate service endpoint.
- `MISP_URL` and `MISP_API_KEY` must be configured together. **If `MISP_URL` is set while `MISP_API_KEY` is empty, the server fails configuration validation.** Use a read-only MISP key and set `MISP_VERIFYCERT=true`.

Example MISP configuration:

```bash
export MISP_URL="https://misp.example.go.id"
export MISP_API_KEY="<misp_readonly_key>"
export MISP_VERIFYCERT="true"
export MISP_CACHE_TTL="900"
export MISP_MIN_INTERVAL="1"
export MISP_MAX_CONCURRENT="2"
export MISP_TIMEOUT="20"
```

### 13.2 Provider quotas, pacing, caching, and base URLs

RapidAPI shares a single account-wide quota pool. The default call budget is `0`, so RapidAPI calls are rejected until an operator enables a budget for a specific need. Example settings:

```bash
export BLUETEAM_RAPIDAPI_BUDGET="0"
export BLUETEAM_RAPIDAPI_BUDGET_HOURS="8"
export BLUETEAM_RAPIDAPI_MONTHLY_CAP="100"
export BLUETEAM_RAPIDAPI_RAW_WHOIS="true"
export BLUETEAM_RAPIDAPI_MIN_INTERVAL="0.25"
export BLUETEAM_RAPIDAPI_CACHE="/var/log/blue-team-mcp/rapidapi_state.jsonl"
export RAPIDAPI_CACHE_TTL="604800"

export NETRA_VERIFY_SSL="true"
export NETRA_MIN_INTERVAL="30"
export ARGUS_VERIFY_SSL="true"
export ARGUS_MIN_INTERVAL="30"
export SANGFOR_MIN_INTERVAL="5"
export SANGFOR_BLOCKLIST_URL="https://blocklist.example.internal/path"
export SANGFOR_BLOCKLIST_TOKEN="<token_if_required>"
export SANGFOR_BLOCKLIST_TIMEOUT="15"
export SANGFOR_BLOCKLIST_VERIFY_SSL="true"
```

`BLUETEAM_RAPIDAPI_BUDGET` deliberately fails closed. Do not increase it substantially without understanding the quota impact. `BLUETEAM_RAPIDAPI_BUDGET_HOURS` limits the budget window; `BLUETEAM_RAPIDAPI_MONTHLY_CAP` is the shared monthly ceiling for the account.

General cache TTLs:

| Variable | Default | Unit/usage |
|---|---:|---|
| `CROWDSEC_CACHE_TTL` | `900` | Seconds. |
| `THREATFOX_CACHE_TTL` | `900` | Seconds. |
| `OTX_CACHE_TTL` | `1800` | Seconds. |
| `URLHAUS_CACHE_TTL` | `1800` | Seconds. |
| `RAPIDAPI_CACHE_TTL` | `604800` | Seconds (7 days). |
| `BLUETEAM_GRAPH_CACHE_TTL` | `60` | Seconds for attack-graph cache. |
| `BLUETEAM_INDEXER_CACHE_TTL` | `30` | Seconds to avoid repeated identical Indexer aggregations; `0` disables the cache. |

Set `SANGFOR_BLOCKLIST_URL` and `SANGFOR_BLOCKLIST_TOKEN` only if your organization uses a compatible blocklist service; do not copy the example endpoint as an active value. `SANGFOR_BLOCKLIST_VERIFY_SSL` should be `true`, and the token must be stored as a secret. Provider base URLs usually do not need to be changed. For an internal proxy/mirror, the script provides `GREYNOISE_BASE_URL`, `CROWDSEC_BASE_URL`, `THREATFOX_BASE_URL`, `OTX_BASE_URL`, `URLHAUS_BASE_URL`, `ABUSEIPDB_BASE_URL`, `VIRUSTOTAL_BASE_URL`, `NETRA_BASE_URL`, `RDAP_BASE_URL`, `CRTSH_BASE_URL`, `HUDSONROCK_BASE_URL`, and specific settings such as `ARGUS_BASE_URL`/`SANGFOR_BLOCKLIST_URL`. Change these only if the alternative endpoint is compatible and trusted.

### 13.3 MITRE ATT&CK STIX and STIX export

MITRE ATT&CK STIX is used for ATT&CK enrichment/knowledge. In general, keep the default URL unless you provide a local mirror:

```bash
export MITRE_ATTACK_STIX="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json"
export BLUETEAM_STIX_CACHE="/var/log/blue-team-mcp/mitre_enterprise_attack.json"
export BLUETEAM_STIX_MAX_AGE_DAYS="7"
export BLUETEAM_STIX_MAX_MB="100"
export BLUETEAM_STIX_RETRY_S="60"
```

Parameters such as `BLUETEAM_STIX_MAX_AGE_DAYS`, `BLUETEAM_STIX_MAX_MB`, and `BLUETEAM_STIX_RETRY_S` limit cache age, download size, and retry delay. For installations with restricted egress, use an approved local mirror file and ensure the service has the correct read permissions.

STIX 2.1 export outside the perimeter is disabled by default. Enable it only after the indicator-sharing process has been reviewed:

```bash
export BLUETEAM_STIX_EGRESS_ENABLED="false"
export BLUETEAM_STIX_IDENTITY_NAME="Organization Name"
export BLUETEAM_STIX_IDENTITY_SECTORS="government"
export BLUETEAM_STIX_IDENTITY_CONTACT="csirt@example.go.id"
export BLUETEAM_STIX_DEFAULT_TLP="AMBER"
export BLUETEAM_STIX_NAMESPACE=""
export BLUETEAM_STIX_MARKINGS_FILE=""
```

Setting `BLUETEAM_STIX_EGRESS_ENABLED=true` requires a correct organization identity and `BLUETEAM_OWNED_DOMAINS`. Review TLP classification, the fields to be shared, and data-owner approval. Do not enable export outside the perimeter before review.

### 13.4 Audit logs, history, and persistence

State paths must be absolute and writable by the service. Example:

```bash
export BLUETEAM_AUDIT_LOG="/var/log/blue-team-mcp/audit.log"
export BLUETEAM_INVESTIGATION_HISTORY="/var/log/blue-team-mcp/investigation_history.jsonl"
export BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES="10000"
export BLUETEAM_EXPORT_DIR="/var/log/blue-team-mcp/exports"

export BLUETEAM_IOC_STORE="/var/log/blue-team-mcp/ioc_store.jsonl"
export BLUETEAM_IOC_STORE_MAX="50000"
export BLUETEAM_IOC_STORE_TTL="7776000"
export BLUETEAM_ATTACKER_REGISTRY="/var/log/blue-team-mcp/attacker_registry.jsonl"
export BLUETEAM_ATTACKER_REGISTRY_TTL="604800"
export BLUETEAM_ATTACKER_REGISTRY_MAX="10000"
export BLUETEAM_FALSE_POSITIVE_KB="/var/log/blue-team-mcp/false_positive_kb.jsonl"
export BLUETEAM_FALSE_POSITIVE_TTL="2592000"
export BLUETEAM_FALSE_POSITIVE_MAX="5000"
export BLUETEAM_CASE_STORE="/var/log/blue-team-mcp/cases.jsonl"
export BLUETEAM_CASE_MAX="500"
export BLUETEAM_CAMPAIGN_SNAPSHOTS="/var/log/blue-team-mcp/campaign_snapshots.jsonl"
export BLUETEAM_CMDB_FILE="/var/log/blue-team-mcp/cmdb_inventory.json"
export BLUETEAM_AUTO_PROMOTE_IPS="false"
```

TTL units are seconds: `7776000` = 90 days, `604800` = 7 days, and `2592000` = 30 days. Note that some stores contain IP addresses, investigation notes, or sensitive derived data. Restrict access and back up the data; retention and deletion policies must follow your organization's policies.

`BLUETEAM_EXPORT_RETENTION_DAYS` controls retention of export artifacts where the relevant feature supports it; the default `0` means no automatic retention is requested through this setting. `BLUETEAM_AUTO_PROMOTE_IPS=false` preserves human review before IPs from high-confidence clusters are automatically registered. Do not change it to `true` without testing and operator approval. Define data-cleanup procedures explicitly.

### 13.5 LangGraph thread persistence and investigation memory

These two options serve different purposes; do not enable them without understanding what data will be persisted.

```bash
# LangGraph: opt-in; if unset, this path does not provide durable persistence
export BLUETEAM_LANGGRAPH_DB="/var/log/blue-team-mcp/langgraph.db"
export BLUETEAM_LANGGRAPH_NODE_TIMEOUT="120"

# Analyst decision memory: both variables below are required to enable the feature
export BLUETEAM_MEM_ENABLED="true"
export BLUETEAM_MEM_DB="/var/log/blue-team-mcp/memory.db"
export BLUETEAM_MEM_MAX_UNITS_PER_SUBJECT="50"
export BLUETEAM_MEM_TTL="7776000"
```

Create the database with a parent directory that is writable by the service. `BLUETEAM_MEM_DB` must be an absolute path; validation rejects `BLUETEAM_MEM_ENABLED=true` if the DB path is incorrect. Memory may contain decisions and analyst reasoning, so restrict access, retention, and deletion procedures. In the relevant implementation, `BLUETEAM_MEM_TTL=0` means entries do not expire; do not choose that value without explicit consideration.

### 13.6 Local case RAG and reranker

**Local case RAG is disabled by default.** RAG uses a local SQLite database for cases, confirmed false positives, or playbooks. Its main settings are:

```bash
export BLUETEAM_RAG_ENABLED="false"
export BLUETEAM_RAG_DB="/opt/blue-team-mcp/rag.db"
export BLUETEAM_RAG_MODEL="BAAI/bge-small-en-v1.5"
export BLUETEAM_RAG_CACHE_PATH="/opt/blue-team-mcp/rag-cache"
export BLUETEAM_RAG_ALLOW_DOWNLOAD="false"
export BLUETEAM_RAG_MAX_CANDIDATES="100"
export BLUETEAM_RAG_TOP_K="10"
export BLUETEAM_RAG_MAX_CHUNKS="50000"
export BLUETEAM_RAG_CHUNK_CHARS="1200"
export BLUETEAM_RAG_CHUNK_OVERLAP="200"
export BLUETEAM_RAG_CHUNK_STRATEGY="sentences"
export BLUETEAM_RAG_VECTOR_WEIGHT="1.0"
export BLUETEAM_RAG_MODEL_SHA256=""
export BLUETEAM_RAG_PARENT_CHILD="false"
export BLUETEAM_RAG_QUERY_NORMALIZE="false"
```

- `BLUETEAM_RAG_ENABLED=true` requires `BLUETEAM_RAG_DB` to be an absolute path; the server rejects the configuration if that path is missing.
- The embedding model is not automatically downloaded by the default runtime configuration. Prepare/cache the model locally through an approved deployment process before enabling RAG, then verify the matching hash. `BLUETEAM_RAG_ALLOW_DOWNLOAD=false` and offline mode prevent runtime downloads.
- `MAX_CANDIDATES` controls the initial candidate set; `TOP_K` controls the number of final results; `MAX_CHUNKS` limits the corpus size.
- `CHUNK_CHARS`/`CHUNK_OVERLAP` control text segmentation. Depending on the implementation, `CHUNK_STRATEGY` can be `sentences`, `paragraphs`, or `length`.
- `VECTOR_WEIGHT=1.0` means vector-only retrieval; values below `1.0` mix in lexical scores according to the project's logic.
- `PARENT_CHILD` and `QUERY_NORMALIZE` are retrieval options that are disabled by default. Test retrieval quality on representative data before enabling them.

Reranker settings:

```bash
export BLUETEAM_RERANK_ENABLED="true"
export BLUETEAM_RERANK_MODEL="BAAI/bge-reranker-base"
export BLUETEAM_RERANK_CACHE_PATH="/opt/blue-team-mcp/rerank-cache"
export BLUETEAM_RERANK_MAX_CANDIDATES="100"
export BLUETEAM_RERANK_MODEL_SHA256=""
export BLUETEAM_RERANK_ALLOW_DOWNLOAD="false"
export BLUETEAM_RERANK_NORMALIZE="false"
```

The default setup downloads and pins the local reranker model. `BLUETEAM_RERANK_MODEL_PATH` is used when you provide a local model snapshot (including `config.json`, `onnx/model.onnx`, and tokenizer files). `BLUETEAM_RERANK_MODEL_SHA256` serves as an ONNX integrity pin when used. Do not change the model name based only on similar naming; an unknown model will cause startup validation to fail rather than silently falling back.

### 13.7 Clustering, forecasting, and source forecasting

HDBSCAN clustering and some forecasting features are disabled by default, and some require optional installation dependencies. Install them first using the flags in Section 5.3, then enable the corresponding configuration.

**Clustering:**

```bash
export BLUETEAM_CLUSTER_ENABLED="false"
export BLUETEAM_CLUSTER_STORE="/var/log/blue-team-mcp/clusters.db"
export BLUETEAM_CLUSTER_STORE_MAX="20000"
export BLUETEAM_CLUSTER_TTL="86400"
export BLUETEAM_CLUSTER_MAX_FITS="100"
export BLUETEAM_CLUSTER_MIN_SIZE="5"
export BLUETEAM_CLUSTER_MIN_SAMPLES="3"
export BLUETEAM_CLUSTER_ASSIGN_FACTOR="1.0"
export BLUETEAM_CLUSTER_LINEAGE_MIN_FITS="2"
export BLUETEAM_CLUSTER_LINEAGE_MATCH_FACTOR="1.5"
export BLUETEAM_CLUSTER_LINEAGE_MIN_POINTS="3"
export BLUETEAM_CLUSTER_LINEAGE_SHIFT_Z="2.5"
export BLUETEAM_CLUSTER_LINEAGE_TACTIC_SHIFT="0.25"
```

**Tactic-sequence forecasting** (the `HMM` parameters require the optional HMM dependency):

```bash
export BLUETEAM_FORECAST_ENABLED="false"
export BLUETEAM_FORECAST_STORE="/var/log/blue-team-mcp/forecast.db"
export BLUETEAM_FORECAST_STORE_MAX="200000"
export BLUETEAM_FORECAST_RETENTION_DAYS="365"
export BLUETEAM_FORECAST_ALPHA="1.0"
export BLUETEAM_FORECAST_MIN_SEQUENCES="5"
export BLUETEAM_FORECAST_MIN_TRANSITIONS="20"
export BLUETEAM_FORECAST_MIN_SUPPORT="3"
export BLUETEAM_FORECAST_HMM_COMPONENTS="4"
export BLUETEAM_FORECAST_HMM_MIN_SEQUENCES="15"
export BLUETEAM_FORECAST_HMM_ITER="50"
export BLUETEAM_FORECAST_HMM_SEED="42"
export BLUETEAM_FORECAST_VOLUME_MIN_BUCKETS="48"
export BLUETEAM_FORECAST_VOLUME_COMPONENTS="3"
export BLUETEAM_FORECAST_VOLUME_HORIZON="24"
export BLUETEAM_FORECAST_VOLUME_CONTEXT="24"
export BLUETEAM_FORECAST_FETCH_PAGE_SIZE="1000"
export BLUETEAM_FORECAST_MAX_HITS="100000"
export BLUETEAM_FORECAST_REQUIRE_COMPLETE_CORPUS="false"
```

**Observed-source forecasting** estimates candidate sources that have been observed; it is not actor attribution. The store contains sensitive data or data closely related to PII:

```bash
export BLUETEAM_SOURCE_FORECAST_ENABLED="false"
export BLUETEAM_SOURCE_STORE="/var/log/blue-team-mcp/source.db"
export BLUETEAM_SOURCE_HISTORY_DAYS="90"
export BLUETEAM_SOURCE_MAX_ROWS="200000"
export BLUETEAM_SOURCE_RETENTION_DAYS="365"
export BLUETEAM_SOURCE_MIN_OBSERVATIONS="20"
export BLUETEAM_SOURCE_MIN_TRANSITIONS="5"
export BLUETEAM_SOURCE_HALF_LIFE_DAYS="14"
export BLUETEAM_SOURCE_MAX_CANDIDATES="10"
export BLUETEAM_SOURCE_NETBLOCK_V4="24"
export BLUETEAM_SOURCE_NETBLOCK_V6="64"
export BLUETEAM_SOURCE_INCLUDE_INTERNAL="false"
export BLUETEAM_SOURCE_MIN_GEO_COVERAGE="0.2"
export BLUETEAM_SOURCE_REQUIRE_COMPLETE_CORPUS="true"
export BLUETEAM_SOURCE_EVAL_HORIZON_MINUTES="1440"
export BLUETEAM_SOURCE_EVAL_STEP_DAYS="1"
export BLUETEAM_SOURCE_EVAL_MIN_TRAIN_OBSERVATIONS="100"
```

Enabling source forecasting requires an absolute `BLUETEAM_SOURCE_STORE` path and data that meets the configured thresholds. Do not infer an actor's identity from forecasts or statistical correlations alone.

### 13.8 Laya/ONNX/SetFit incident labeling

Incident labeling does not become a full model-based labeler simply by setting `BLUETEAM_LAYA_ENABLED=true`. The backend, dependencies, artifacts, paths, and hashes must all match:

```bash
export BLUETEAM_LAYA_ENABLED="false"
export BLUETEAM_LAYA_BACKEND="onnx"
export BLUETEAM_LAYA_MODEL_PATH=""
export BLUETEAM_LAYA_MODEL_SHA256=""
export BLUETEAM_LAYA_ALLOW_DOWNLOAD="false"
export BLUETEAM_LAYA_CONFIDENCE_FLOOR="0.6"
export BLUETEAM_LAYA_TEMPERATURE=""
export BLUETEAM_LAYA_MAX_LEN="1024"
export BLUETEAM_LAYA_MAX_CONCURRENCY="1"
```

- The `onnx` backend is designed to use the embedding model used by RAG; make sure the required artifacts are actually available.
- The `laya` backend requires `BLUETEAM_INSTALL_LAYA=1`, local model weights, and a pinned hash.
- The `setfit` backend requires `BLUETEAM_INSTALL_SETFIT=1`, local weights, and a pinned hash.
- `BLUETEAM_LAYA_CONFIDENCE_FLOOR` is the confidence threshold; results below it are marked `uncertain` rather than being forced into a label.
- `BLUETEAM_LAYA_TEMPERATURE` controls probability calibration. The optimal value must be determined from evaluation data, not changed merely to produce more labels.
- Runtime model downloads are disabled by default. Use curated and verified model artifacts, especially on staging/production servers.

### 13.9 Detection engineering / staging rules

The following rule directories are intended for **staging**, not the live paths automatically loaded by Wazuh:

```bash
export BLUETEAM_YARA_RULES_DIR="/opt/yara_rules/yara_staging"
export BLUETEAM_SIGMA_RULES_DIR="/opt/sigma_rules/sigma_staging"
export BLUETEAM_SIGMA_INDEX_PATTERN="wazuh-alerts-*"
export BLUETEAM_SIGMA_MONITOR_INTERVAL="5"
export BLUETEAM_SIGMA_VERIFY_FIELDS="true"
export BLUETEAM_SIGMA_CHECK_EXISTING="true"
```

Recommended workflow: generate → validate → test mappings/overlap → human review → manually promote to the live rules directory through change control. Do not point directly to the live Wazuh directory to bypass review.

### 13.10 Beacon, allowlists, owned domains, and host capture

Additional variables that may be useful:

```bash
export BLUETEAM_BEACON_EXCLUDE_IPS="10.0.0.1,10.0.0.2"
export BLUETEAM_OWNED_DOMAINS="example.go.id,example.org"
export ALLOWED_INTERNAL_DOMAINS="internal.example.go.id"
export BLUETEAM_ALLOWED_PATHS="/var:/etc:/home:/opt:/usr"
export BLUETEAM_CAPTURE_DIR="/tmp"
```

Replace placeholders with the organization's official inventory. Do not put third-party IPs/domains on an allowlist unless authorization and the testing scope explicitly cover them.

## 14. CPU/offline environment variables set by the installer

`setup.sh` synchronizes thread settings to `config.env` and `.env` to limit CPU usage by model pools:

```bash
export USE_TF="0"
export USE_FLAX="0"
export TOKENIZERS_PARALLELISM="false"
export HF_HUB_OFFLINE="1"
export TRANSFORMERS_OFFLINE="1"
export OMP_NUM_THREADS="2"
export MKL_NUM_THREADS="2"
export OPENBLAS_NUM_THREADS="2"
export NUMEXPR_NUM_THREADS="2"
```

A thread setting of `2` is a conservative starting point, not a universal benchmark result. On a small CPU, do not allow multiple models/workers to consume all system threads. `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE` follow the RAG/labeler download permissions in the setup logic. Do not enable runtime downloads unless there is a clear reason, required egress access, and a known target artifact.

## 15. Restart, troubleshooting, updates, and backups

### Restart after editing the configuration

```bash
sudo bash -n /opt/blue-team-mcp/config.env
sudo systemctl restart blue-team-mcp
sudo systemctl status blue-team-mcp --no-pager
sudo journalctl -u blue-team-mcp -n 100 --no-pager
```

Not all errors can be detected by `bash -n`. Check application logs for URL/secret validation and dependency errors, but do not publish logs containing sensitive information.

### Troubleshooting

| Symptom | Checks |
|---|---|
| Installer fails before completion | Check Python `>=3.11`, DNS, package access, disk space, and `setup.sh` output. Review the optional installation block being executed. |
| Process stalls during reranker bootstrap | Make sure disk space/bandwidth is sufficient, or install with `BLUETEAM_RERANK_ENABLED=false`; do not enable it again until a valid model is available. |
| Startup reports an invalid `WAZUH_INDEXER_URL`/password | Set `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, and `WAZUH_INDEXER_PASSWORD`; make sure the wrapper reads the file. |
| Server cannot read `config.env` | Check `User=blueteam-mcp`, `Group=blueteam-mcp`, ownership `root:blueteam-mcp`, mode `640`, and group membership. |
| HTTP returns `401 Unauthorized` | The API key is missing/incorrect, or the `Authorization: Bearer ...` header was not sent. If the key is enabled, even loopback requests must send a bearer token. |
| A specific tool returns `403` | Check `MCP_API_KEY_SCOPES`, `WAZUH_READ_ONLY`, `WAZUH_DISABLED_CATEGORIES`, and `WAZUH_DISABLED_TOOLS`. Do not enable write scopes unless needed. |
| Wazuh Indexer cannot be reached | Check DNS, routing, firewall, port `9200`, Indexer account/role, HTTPS URL, and TLS CA. |
| Manager API is inactive while the Indexer works | The Manager API is optional; check URL/port `55000`, username/password, API permissions, firewall, and certificate. |
| MISP causes the server to fail at startup | If `MISP_URL` is set, `MISP_API_KEY` must also be set. Verify the MISP certificate when `MISP_VERIFYCERT=true`. |
| An optional tool reports `unavailable` | Check the dependency installation flag, the runtime `*_ENABLED` flag, absolute paths, store permissions, local model artifacts, and pinned hashes. A runtime flag does not install dependencies by itself. |
| Service cannot write to an export/store | Make sure the parent directory exists, the service can write to it, and the unit's `ReadWritePaths` includes the location if `systemd` hardening is enabled. |
| Changes have no effect | Make sure you edited `/opt/blue-team-mcp/config.env`, the file syntax is valid, and the service was restarted; changing only the repository copy is not enough. |

### Update safely

Before updating, back up the configuration file and state data. Run the update from the same clone:

```bash
cd /path/to/Wazuh-MCP-Server
git status --short
git pull --ff-only
# Review changes to setup.sh, requirements.txt, README, and the changelog
sudo bash setup.sh
sudo systemctl restart blue-team-mcp
sudo systemctl status blue-team-mcp --no-pager
```

Do not perform blind updates on a production server. The installer copies new source code to `/opt/blue-team-mcp`, may update dependencies, and preserves the existing `config.env`; review breaking changes and perform a smoke test after updating.

## 16. Pre-production checklist

- [ ] Python 3.11+ is installed and the source commit has been recorded.
- [ ] `WAZUH_INDEXER_URL`, username, password, and TLS have been verified successfully.
- [ ] The Manager API is configured only if actually needed.
- [ ] `config.env` contains the correct secrets and has permissions `root:blueteam-mcp` with mode `640`.
- [ ] The unit runs as `blueteam-mcp`, not root.
- [ ] `WAZUH_READ_ONLY=true` and `MCP_API_KEY_SCOPES="wazuh:read"` are used as the baseline.
- [ ] MCP HTTP binds only to loopback; HTTPS/VPN/firewall/API-key controls are in place for remote access.
- [ ] No internal Wazuh or MCP ports are exposed to the internet without an approved security policy.
- [ ] Redaction is enabled; forensic bypass/identity reveal remain disabled unless approved.
- [ ] Owned domains, internal allowlists, and filesystem paths have been customized; examples have not been used without review.
- [ ] Log, state, database, and export directories have appropriate permissions and retention policies.
- [ ] Optional model/ML features are enabled only when dependencies, artifacts, integrity checks, host resources, and evaluations are ready.
- [ ] The MCP handshake has been tested, and the Wazuh connection has then been tested using a read-only tool. `systemd` status alone does not prove the integration works.
- [ ] Backup/rollback and update procedures have been defined.

## 17. References

- Repository: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server>
- README: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/README.md>
- Setup script: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/setup.sh>
- Python dependencies: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/requirements.txt>
- Main entry point: <https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/main.py>
