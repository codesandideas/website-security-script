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
        echo -e "${BOLD}  EXCLUDE_PATTERN:${NC} ${EXCLUDE_PATTERN}"
        echo -e "${BOLD}  MAX_FILE_SIZE:${NC}   ${MAX_FILE_SIZE}"
        echo -e "${BOLD}  SCAN_TIMEOUT:${NC}    ${SCAN_TIMEOUT}s"
        echo -e "${BOLD}  SHOW_RECOMMENDATIONS:${NC} ${SHOW_RECOMMENDATIONS}"
    else
        echo "  No config file found. Run a --set-* command to create one."
    fi
    echo ""
    exit 0
}
