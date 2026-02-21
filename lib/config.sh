# ── Configuration Defaults ───────────────────────────────────────────────────
SCAN_DIR=""
SITE_URL=""
WEBHOOK_URL=""
API_KEY=""
NOTIFY_EMAIL=""
EMAIL_ENABLED=false
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
REPORT_FILE=""
TEMP_DIR=$(mktemp -d)
TOTAL_ISSUES=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
INFO=0

# ── Scan Configuration ─────────────────────────────────────────────────────────
EXCLUDE_PATTERN='node_modules|vendor/|\.git/|venv/|__pycache__|dist/|build/|\.next/|cache/|\.svn/|\.hg/'
MAX_FILE_SIZE="10M"  # Skip files larger than 10MB
TIMEOUT_CMD="timeout 30"  # Prevent hanging on slow operations
SCAN_TIMEOUT=300  # Maximum total scan duration in seconds
FILE_LIST=""  # Will be set after temp dir creation
BACKGROUND=false  # Run scan in background
MAX_PARALLEL=4    # Maximum parallel scan sections
SHOW_RECOMMENDATIONS=true  # Show recommendations section in report
LOG_DIR="${REAL_HOME:-$HOME}/.config/webscan/logs"

# ── Scan Mode ─────────────────────────────────────────────────────────────────
# all    = run every section (default)
# files  = file-based scans only — safe on shared hosting, no server access needed
# server = server-level checks only — requires root/server access
SCAN_MODE="all"

# ── Module Toggles ────────────────────────────────────────────────────────────
# FILE-BASED scans — analyse code on disk, work on any shared hosting
SCAN_01_MALWARE=true          # Malware & backdoor signatures
SCAN_02_SUSPICIOUS=true       # Suspicious file patterns & code
SCAN_03_OBFUSCATION=true      # Obfuscated / encoded code detection
SCAN_04_INTEGRITY=true        # File integrity & symlink anomalies
SCAN_05_FRAMEWORK=true        # Framework-specific security audit
SCAN_06_DEPENDENCIES=true     # Dependency & supply-chain risk checks
SCAN_07_PERMISSIONS=true      # File & directory permission audit
SCAN_09_SECRETS=true          # Secrets & credential exposure
SCAN_11_MODIFIED_FILES=true   # Recently modified files tracker

# SERVER-LEVEL scans — require access to server config, ports, processes
# On shared hosting the server is managed by the host — disable these to avoid
# false-positives and wasted scan time.
SCAN_08_SERVER_CONFIG=true    # Web server config (Apache/Nginx/PHP)
SCAN_10_NETWORK=true          # Network, CORS & suspicious crontab entries
SCAN_12_SSL=true              # SSL/TLS certificate & cipher checks
SCAN_13_DATABASE=true         # Database port exposure & credential checks
SCAN_14_CONTAINER=true        # Container / Docker security checks
SCAN_15_LOGGING=true          # Logging & monitoring verification

# ── SMTP Configuration ──────────────────────────────────────────────────────
SMTP_HOST=""
SMTP_USER=""
SMTP_PASS=""
SMTP_FROM=""

# ── Config File ──────────────────────────────────────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")
CONFIG_DIR="${REAL_HOME}/.config/webscan"
CONFIG_FILE="${CONFIG_DIR}/config"

# Load config file if it exists (values become defaults)
if [[ -f "$CONFIG_FILE" ]]; then
    # Source only known variables to avoid injection
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        # Trim whitespace
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs | sed 's/^["'\''"]//;s/["'\''"]$//')
        case "$key" in
            NOTIFY_EMAIL)    NOTIFY_EMAIL="$value" ;;
            EMAIL_ENABLED)   EMAIL_ENABLED="$value" ;;
            WEBHOOK_URL)     WEBHOOK_URL="$value" ;;
            API_KEY)         API_KEY="$value" ;;
            EXCLUDE_PATTERN) EXCLUDE_PATTERN="$value" ;;
            MAX_FILE_SIZE)   MAX_FILE_SIZE="$value" ;;
            TIMEOUT_CMD)     TIMEOUT_CMD="$value" ;;
            SCAN_TIMEOUT)    SCAN_TIMEOUT="$value" ;;
            SHOW_RECOMMENDATIONS) SHOW_RECOMMENDATIONS="$value" ;;
            MAX_PARALLEL) MAX_PARALLEL="$value" ;;
            USE_ALLOWLIST) USE_ALLOWLIST="$value" ;;
            SCAN_MODE) SCAN_MODE="$value" ;;
            SCAN_01_MALWARE)        SCAN_01_MALWARE="$value" ;;
            SCAN_02_SUSPICIOUS)     SCAN_02_SUSPICIOUS="$value" ;;
            SCAN_03_OBFUSCATION)    SCAN_03_OBFUSCATION="$value" ;;
            SCAN_04_INTEGRITY)      SCAN_04_INTEGRITY="$value" ;;
            SCAN_05_FRAMEWORK)      SCAN_05_FRAMEWORK="$value" ;;
            SCAN_06_DEPENDENCIES)   SCAN_06_DEPENDENCIES="$value" ;;
            SCAN_07_PERMISSIONS)    SCAN_07_PERMISSIONS="$value" ;;
            SCAN_08_SERVER_CONFIG)  SCAN_08_SERVER_CONFIG="$value" ;;
            SCAN_09_SECRETS)        SCAN_09_SECRETS="$value" ;;
            SCAN_10_NETWORK)        SCAN_10_NETWORK="$value" ;;
            SCAN_11_MODIFIED_FILES) SCAN_11_MODIFIED_FILES="$value" ;;
            SCAN_12_SSL)            SCAN_12_SSL="$value" ;;
            SCAN_13_DATABASE)       SCAN_13_DATABASE="$value" ;;
            SCAN_14_CONTAINER)      SCAN_14_CONTAINER="$value" ;;
            SCAN_15_LOGGING)        SCAN_15_LOGGING="$value" ;;
            SMTP_HOST)              SMTP_HOST="$value" ;;
            SMTP_USER)              SMTP_USER="$value" ;;
            SMTP_PASS)              SMTP_PASS="$value" ;;
            SMTP_FROM)              SMTP_FROM="$value" ;;
        esac
    done < "$CONFIG_FILE"
fi

# ── Config Helper Functions ──────────────────────────────────────────────────
config_set() {
    local key="$1" value="$2"
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "${key}=${value}" > "$CONFIG_FILE"
        chown "${REAL_USER}:$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")" "$CONFIG_DIR" "$CONFIG_FILE" 2>/dev/null || true
    elif grep -q "^${key}=" "$CONFIG_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$CONFIG_FILE"
    else
        echo "${key}=${value}" >> "$CONFIG_FILE"
    fi
    echo -e "${GREEN}[OK]${NC} ${key} set to: ${value}"
}

config_show() {
    echo ""
    echo -e "${BOLD}Web Security Scanner - Current Configuration${NC}"
    echo -e "${CYAN}Config file:${NC} ${CONFIG_FILE}"
    echo ""
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${BOLD}  NOTIFY_EMAIL:${NC}    ${NOTIFY_EMAIL:-<not set>}"
        echo -e "${BOLD}  EMAIL_ENABLED:${NC}   ${EMAIL_ENABLED}"
        echo -e "${BOLD}  WEBHOOK_URL:${NC}     ${WEBHOOK_URL:-<not set>}"
        echo -e "${BOLD}  API_KEY:${NC}         ${API_KEY:+****${API_KEY: -4}}"
        [[ -z "$API_KEY" ]] && echo -e "${BOLD}  API_KEY:${NC}         <not set>"
        echo ""
        echo -e "${BOLD}  SMTP_HOST:${NC}       ${SMTP_HOST:-<not set>}"
        echo -e "${BOLD}  SMTP_USER:${NC}       ${SMTP_USER:-<not set>}"
        echo -e "${BOLD}  SMTP_PASS:${NC}       ${SMTP_PASS:+****${SMTP_PASS: -2}}"
        [[ -z "$SMTP_PASS" ]] && echo -e "${BOLD}  SMTP_PASS:${NC}       <not set>"
        echo -e "${BOLD}  SMTP_FROM:${NC}       ${SMTP_FROM:-<not set>}"
        echo ""
        echo -e "${BOLD}  EXCLUDE_PATTERN:${NC} ${EXCLUDE_PATTERN}"
        echo -e "${BOLD}  MAX_FILE_SIZE:${NC}   ${MAX_FILE_SIZE}"
        echo -e "${BOLD}  SCAN_TIMEOUT:${NC}    ${SCAN_TIMEOUT}s"
        echo -e "${BOLD}  SHOW_RECOMMENDATIONS:${NC} ${SHOW_RECOMMENDATIONS}"
        echo ""
        echo -e "${BOLD}  SCAN_MODE:${NC}           ${SCAN_MODE}  (all | files | server)"
        echo ""
        echo -e "${BOLD}  Module Toggles (File-Based):${NC}"
        echo -e "    SCAN_01_MALWARE=${SCAN_01_MALWARE}  SCAN_02_SUSPICIOUS=${SCAN_02_SUSPICIOUS}  SCAN_03_OBFUSCATION=${SCAN_03_OBFUSCATION}"
        echo -e "    SCAN_04_INTEGRITY=${SCAN_04_INTEGRITY}  SCAN_05_FRAMEWORK=${SCAN_05_FRAMEWORK}  SCAN_06_DEPENDENCIES=${SCAN_06_DEPENDENCIES}"
        echo -e "    SCAN_07_PERMISSIONS=${SCAN_07_PERMISSIONS}  SCAN_09_SECRETS=${SCAN_09_SECRETS}  SCAN_11_MODIFIED_FILES=${SCAN_11_MODIFIED_FILES}"
        echo ""
        echo -e "${BOLD}  Module Toggles (Server-Level):${NC}"
        echo -e "    SCAN_08_SERVER_CONFIG=${SCAN_08_SERVER_CONFIG}  SCAN_10_NETWORK=${SCAN_10_NETWORK}  SCAN_12_SSL=${SCAN_12_SSL}"
        echo -e "    SCAN_13_DATABASE=${SCAN_13_DATABASE}  SCAN_14_CONTAINER=${SCAN_14_CONTAINER}  SCAN_15_LOGGING=${SCAN_15_LOGGING}"
    else
        echo "  No config file found. Run a --set-* command to create one."
    fi
    echo ""
    exit 0
}
