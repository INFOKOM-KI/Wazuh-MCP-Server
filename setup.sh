#!/usr/bin/env bash
# Blue Team Wazuh MCP Server Setup Script
# Programmer : NAuliajati (csirt@tangerangkota.go.id)
# © TangerangKota-CSIRT
set -e

INSTALL_DIR="/opt/blue-team-mcp"
SERVICE_USER="blueteam-mcp"

echo "=============================================="
echo "  Blue Team Wazuh MCP Server - Setup"
echo "=============================================="

# Root check
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash setup.sh"
  exit 1
fi

# Install system dependencies
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-venv \
  tcpdump \
  fail2ban \
  rkhunter \
  chkrootkit \
  lynis \
  net-tools \
  iproute2 \
  procps \
  openssh-server \
  2>/dev/null || true

echo "[2/7] Creating install directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Clean stale bytecode before copying (prevents Python version mismatch issues)
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Copy the server — main.py is the entry point (M14 modular refactor)
cp main.py "$INSTALL_DIR/"
cp -r mcp_server/ "$INSTALL_DIR/mcp_server/"
cp requirements.txt "$INSTALL_DIR/"

# Python venv
echo "[3/7] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
# Optional: run pip-audit if available (MAESTRO supply chain)
"$INSTALL_DIR/venv/bin/pip" install --quiet pip-audit 2>/dev/null && \
  "$INSTALL_DIR/venv/bin/pip-audit" 2>/dev/null || true

# Config file for environment variables
CONFIG_FILE="$INSTALL_DIR/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[4/7] Creating config file at $CONFIG_FILE..."
  cat > "$CONFIG_FILE" << 'CONFIGEOF'
# Blue Team MCP - Environment Variables

# Threat intelligence (optional)
# export THREATFOX_API_KEY="your_key"     # free key: https://threatfox.abuse.ch/api
# export ABUSEIPDB_API_KEY="your_key"     # https://www.abuseipdb.com
# export VIRUSTOTAL_API_KEY="your_key"    # https://www.virustotal.com
# export CROWDSEC_API_KEY="your_key"      # free tier: https://www.crowdsec.net/en/user/profile
# export NETRA_API_KEY="your_key"         # You should MoU to TangerangKota-CSIRT for secret api key.:)
# export NETRA_VERIFY_SSL="false"         # set to "true" for production / trusted CA

# Argus Threat Intelligence (optional — TangerangKota-CSIRT)
# export ARGUS_API_KEY="your_key"         # You should MoU to TangerangKota-CSIRT for secret api key.:)
# export ARGUS_BASE_URL="https://argus.fbi.gov"
# export ARGUS_VERIFY_SSL="false"         # set to "true" for production / trusted CA

# GreyNoise Community — no API key needed; greynoise_ip_context works out of the box.

# External API Base URLs (defaults shown — override for self-hosted mirrors or proxies)
# export GREYNOISE_BASE_URL="https://api.greynoise.io/v3/community"
# export CROWDSEC_BASE_URL="https://cti.api.crowdsec.net"
# export THREATFOX_BASE_URL="https://threatfox-api.abuse.ch/api/v1/"
# export ABUSEIPDB_BASE_URL="https://api.abuseipdb.com/api/v2"
# export VIRUSTOTAL_BASE_URL="https://www.virustotal.com/api/v3"
# export NETRA_BASE_URL="https://netra.fbi.gov:8013/api/v1"
# export RDAP_BASE_URL="https://rdap.org"
# export CRTSH_BASE_URL="https://crt.sh"

# Caching TTLs (seconds — defaults shown)
# export CROWDSEC_CACHE_TTL="900"
# export THREATFOX_CACHE_TTL="900"

# MCP transport (optional — default: stdio for SSH usage)
# Uncomment one for a remote HTTP service:
# export MCP_TRANSPORT="streamable_http"
# export MCP_HOST="0.0.0.0"
# export MCP_PORT="8000"

# Logging level: DEBUG, INFO (default), WARNING, ERROR
# export LOG_LEVEL="INFO"

# Wazuh SIEM (optional)
# export WAZUH_API_URL="https://192.168.1.180:55000"
# export WAZUH_API_USER="wazuh-wui"
# export WAZUH_API_PASSWORD="MyS3cr37P450r.*-"
# export WAZUH_API_VERIFY_SSL="true"   # TLS verification ON by default — disable only for self-signed labs

# Wazuh Indexer / OpenSearch (optional - for HYDRA-DC Windows events, port 9200)
# export WAZUH_INDEXER_URL="https://192.168.1.180:9200"
# export WAZUH_INDEXER_USER="admin"
# export WAZUH_INDEXER_PASSWORD="your_indexer_password"
# export WAZUH_INDEXER_VERIFY_SSL="true"  # TLS verification ON by default — disable only for self-signed labs

# Performance & Response Limits
# export BLUETEAM_CHARACTER_LIMIT="100000"       # max chars per tool response before truncation
# export WAZUH_INDEXER_MAX_SIZE="10000"          # max documents per page in Wazuh Indexer search

# Forensic Mode (ADMIN GATE — off by default)
# export BLUETEAM_ALLOW_UNTRUNCATED="false"

# Sangfor Blocklist Integration (optional — set SANGFOR_BLOCKLIST_TOKEN to enable sangfor_blocklist_* tools)
# export SANGFOR_BLOCKLIST_URL="http://172.16.9.148:8088/blocklist"
# export SANGFOR_BLOCKLIST_TOKEN="your_sangfor_bearer_token"
# export SANGFOR_BLOCKLIST_TIMEOUT="15"
# export SANGFOR_BLOCKLIST_VERIFY_SSL="false"   # set to "true" for production / trusted CA

# Data masking (see SECURITY.md §4 for the six-layer model)
# export BLUETEAM_REDACT_EMAILS="true"
# export BLUETEAM_REDACT_PII="true"
# export BLUETEAM_REDACT_DOMAINS="true"
# export BLUETEAM_REDACT_LOCATIONS="true"
# export BLUETEAM_REDACT_UAS="true"

# Forensic email/path hashing salt (change per deployment)
# export BLUETEAM_REDACT_SALT="change-me-per-deployment"

# Server identity (optional — use lowercase to avoid LLM casing mismatches)
# export BLUE_TEAM_MCP_SERVER_NAME="blue_team_mcp"

# Audit and limits (optional)
# export BLUETEAM_INVESTIGATION_HISTORY="/var/log/blue-team-mcp/investigation_history.jsonl"
# export BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES="10000"
# export BLUETEAM_AUDIT_LOG="/var/log/blue-team-mcp/audit.log"
# export BLUETEAM_RATE_LIMIT="0"

# Path restrictions (defaults shown)
# export BLUETEAM_ALLOWED_PATHS="/var:/etc:/home:/opt:/usr"
# export BLUETEAM_CAPTURE_DIR="/tmp"
CONFIGEOF
  chmod 644 "$CONFIG_FILE"
  echo "  Created $CONFIG_FILE - edit to add API keys and Wazuh credentials"
else
  echo "[4/7] Config file exists at $CONFIG_FILE (not overwritten)"
fi

# Wrapper scripts
echo "[5/7] Creating MCP server wrapper scripts..."

# Main wrapper: mcp-server-blueteam (all 79 tools)
cat > /usr/local/bin/mcp-server-blueteam << 'EOF'
#!/usr/bin/env bash
# Wrapper - Claude Desktop calls this via SSH (MAESTRO-compliant)
[[ -f /opt/blue-team-mcp/config.env ]] && source /opt/blue-team-mcp/config.env
# Threat Intelligence keys
export ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
export VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
export CROWDSEC_API_KEY="${CROWDSEC_API_KEY:-}"
export THREATFOX_API_KEY="${THREATFOX_API_KEY:-}"
export THREATFOX_CACHE_TTL="${THREATFOX_CACHE_TTL:-900}"
export NETRA_API_KEY="${NETRA_API_KEY:-}"
export NETRA_VERIFY_SSL="${NETRA_VERIFY_SSL:-false}"
export ARGUS_API_KEY="${ARGUS_API_KEY:-}"
export ARGUS_BASE_URL="${ARGUS_BASE_URL:-}"
export ARGUS_VERIFY_SSL="${ARGUS_VERIFY_SSL:-false}"
# External API Base URLs
export GREYNOISE_BASE_URL="${GREYNOISE_BASE_URL:-https://api.greynoise.io/v3/community}"
export CROWDSEC_BASE_URL="${CROWDSEC_BASE_URL:-https://cti.api.crowdsec.net}"
export THREATFOX_BASE_URL="${THREATFOX_BASE_URL:-https://threatfox-api.abuse.ch/api/v1/}"
export ABUSEIPDB_BASE_URL="${ABUSEIPDB_BASE_URL:-https://api.abuseipdb.com/api/v2}"
export VIRUSTOTAL_BASE_URL="${VIRUSTOTAL_BASE_URL:-https://www.virustotal.com/api/v3}"
export NETRA_BASE_URL="${NETRA_BASE_URL:-https://yourdreams.gov:8013/api/v1}"
export RDAP_BASE_URL="${RDAP_BASE_URL:-https://rdap.org}"
export CRTSH_BASE_URL="${CRTSH_BASE_URL:-https://crt.sh}"
# Sangfor blocklist
export SANGFOR_BLOCKLIST_URL="${SANGFOR_BLOCKLIST_URL:-}"
export SANGFOR_BLOCKLIST_TOKEN="${SANGFOR_BLOCKLIST_TOKEN:-}"
export SANGFOR_BLOCKLIST_TIMEOUT="${SANGFOR_BLOCKLIST_TIMEOUT:-15}"
export SANGFOR_BLOCKLIST_VERIFY_SSL="${SANGFOR_BLOCKLIST_VERIFY_SSL:-false}"
# Audit and limits
export BLUETEAM_INVESTIGATION_HISTORY="${BLUETEAM_INVESTIGATION_HISTORY:-}"
export BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES="${BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES:-10000}"
export BLUETEAM_AUDIT_LOG="${BLUETEAM_AUDIT_LOG:-}"
export BLUETEAM_RATE_LIMIT="${BLUETEAM_RATE_LIMIT:-0}"
# Data masking (six-layer pipeline)
export BLUETEAM_REDACT_PII="${BLUETEAM_REDACT_PII:-true}"
export BLUETEAM_REDACT_EMAILS="${BLUETEAM_REDACT_EMAILS:-true}"
export BLUETEAM_REDACT_DOMAINS="${BLUETEAM_REDACT_DOMAINS:-true}"
export BLUETEAM_REDACT_LOCATIONS="${BLUETEAM_REDACT_LOCATIONS:-true}"
export BLUETEAM_REDACT_UAS="${BLUETEAM_REDACT_UAS:-true}"
export BLUETEAM_ALLOW_UNTRUNCATED="${BLUETEAM_ALLOW_UNTRUNCATED:-false}"
export BLUETEAM_ALLOWED_PATHS="${BLUETEAM_ALLOWED_PATHS:-/var:/etc:/home:/opt:/usr}"
export BLUETEAM_CAPTURE_DIR="${BLUETEAM_CAPTURE_DIR:-/tmp}"
export BLUETEAM_CHARACTER_LIMIT="${BLUETEAM_CHARACTER_LIMIT:-100000}"
export CROWDSEC_CACHE_TTL="${CROWDSEC_CACHE_TTL:-900}"
export BLUETEAM_REDACT_SALT="${BLUETEAM_REDACT_SALT:-}"
export BLUE_TEAM_MCP_SERVER_NAME="${BLUE_TEAM_MCP_SERVER_NAME:-blue_team_mcp}"
export LOG_LEVEL="${LOG_LEVEL:-INFO}"
# Wazuh
export WAZUH_INDEXER_MAX_SIZE="${WAZUH_INDEXER_MAX_SIZE:-10000}"
export WAZUH_API_URL="${WAZUH_API_URL:-}"
export WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
export WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-}"
export WAZUH_API_VERIFY_SSL="${WAZUH_API_VERIFY_SSL:-true}"
export WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-}"
export WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
export WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-}"
export WAZUH_INDEXER_VERIFY_SSL="${WAZUH_INDEXER_VERIFY_SSL:-true}"
# Transport
export MCP_TRANSPORT="${MCP_TRANSPORT:-stdio}"
export MCP_HOST="${MCP_HOST:-127.0.0.1}"
export MCP_PORT="${MCP_PORT:-8000}"
# Main entry point — modular M14 architecture (main.py + mcp_server/ package)
exec /opt/blue-team-mcp/venv/bin/python3 /opt/blue-team-mcp/main.py "$@"
EOF
chmod +x /usr/local/bin/mcp-server-blueteam

# DEPRECATED standalone wrappers — redirect to the unified server.
for legacy in mcp-server-crowdsec mcp-server-greynoise; do
  cat > "/usr/local/bin/$legacy" << 'EOF'
#!/usr/bin/env bash
echo "[$0] DEPRECATED — redirecting to mcp-server-blueteam (unified server)" >&2
exec /usr/local/bin/mcp-server-blueteam "$@"
EOF
  chmod +x "/usr/local/bin/$legacy"
done

# SSH hardening reminder
echo "[6/7] Ensuring SSH is running..."
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true

# Capability grants (allow tcpdump without root)
echo "[7/7] Granting tcpdump network capture capability..."
setcap cap_net_raw,cap_net_admin=eip "$(which tcpdump)" 2>/dev/null || \
  echo "  WARNING: Could not set tcpdump capabilities. Run captures as root."

# API key configuration
echo ""
echo "=============================================="
echo "  Setup complete!"
echo "=============================================="
echo ""
echo "OPTIONAL: Edit $CONFIG_FILE to add API keys and credentials:"
echo ""
echo "  sudo nano $CONFIG_FILE"
echo ""
echo "  Uncomment and set: THREATFOX_API_KEY, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY,"
echo "  CROWDSEC_API_KEY (free tier at crowdsec.net), NETRA_API_KEY, ARGUS_API_KEY,"
echo "  WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,"
echo "  WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD."
echo ""
echo "  Performance tuning (all optional, defaults shown):"
echo "    BLUETEAM_CHARACTER_LIMIT=100000"
echo "    WAZUH_INDEXER_MAX_SIZE=10000      (docs per page in indexer search)"
echo "    BLUETEAM_ALLOW_UNTRUNCATED=false  (set true for forensic mode)"
echo ""
echo "  GreyNoise Community needs no key — greynoice_ip_context works immediately."
echo "  ThreatFox needs a free key — https://threatfox.abuse.ch/api"
echo ""
echo "Wrapper entry points installed:"
echo ""
echo "  mcp-server-blueteam    — All 79 tools (Wazuh, threat intel, host forensics,"
echo "                            Sangfor blocklist, 3-Sum correlation, curated reports,"
echo "                            CrowdSec, GreyNoise, ThreatFox)"
echo "  mcp-server-crowdsec    — DEPRECATED — redirects to mcp-server-blueteam"
echo "  mcp-server-greynoise   — DEPRECATED — redirects to mcp-server-blueteam"
echo ""
echo "Run as a remote HTTP service (no SSH needed):"
echo ""
echo "  MCP_TRANSPORT=streamable_http MCP_HOST=0.0.0.0 MCP_PORT=8000 mcp-server-blueteam"
echo ""
echo "Then add to your Claude Desktop config on macOS/Windows:"
echo ""
echo "  Option A — Local via SSH:"
echo '  {
    "mcpServers": {
      "blue-team-mcp": {
        "command": "ssh",
        "args": [
          "-i", "/path/to/your/ssh_key",
          "user@DEFENDER_HOST_IP",
          "mcp-server-blueteam"
        ],
        "transport": "stdio"
      }
    }
  }'
echo ""
echo "  Option B — Remote service (no SSH, connects over HTTP):"
echo '  {
    "mcpServers": {
      "blue-team-mcp": {
        "url": "http://DEFENDER_HOST_IP:8000/mcp",
        "transport": "streamable-http"
      }
    }
  }'
echo ""
echo "Test locally first: mcp-server-blueteam"
echo ""
echo "For a persistent remote service, see the systemd unit in README.md."
