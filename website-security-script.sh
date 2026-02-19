#!/bin/bash
# ============================================================================
# Universal Web Security Scanner v3.0
# Comprehensive Malware, Vulnerability & Configuration Auditor
# Supports: WordPress, Laravel, Drupal, Joomla, Magento, CodeIgniter,
#           Node.js/Express, Django, Flask, Next.js, Static Sites, and more
#
# Usage: webscan /path/to/website [options]
# Install: sudo bash install.sh
#
# Output: Markdown report (security-report_YYYY-MM-DD_HH-MM-SS.md)
# ============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration Defaults ───────────────────────────────────────────────────
SCAN_DIR=""
WEBHOOK_URL=""
API_KEY=""
NOTIFY_EMAIL=""
EMAIL_ENABLED=false
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
REPORT_FILE="security-report_${TIMESTAMP}.md"
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
    else
        echo "  No config file found. Run a --set-* command to create one."
    fi
    echo ""
    exit 0
}

# ── Cron Helper Functions ────────────────────────────────────────────────────
CRON_MARKER="# webscan-auto"
WEBSCAN_BIN=$(command -v webscan 2>/dev/null || echo "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")")

cron_schedule_to_expr() {
    case "$1" in
        hourly)  echo "0 * * * *" ;;
        daily)   echo "0 2 * * *" ;;
        weekly)  echo "0 2 * * 0" ;;
        monthly) echo "0 2 1 * *" ;;
        *)       echo "$1" ;;
    esac
}

cron_add() {
    local schedule="$1"
    local scan_path="$2"
    shift 2
    local extra_args="$*"
    local expr
    expr=$(cron_schedule_to_expr "$schedule")

    # Validate cron expression (must have 5 fields)
    local field_count
    field_count=$(echo "$expr" | awk '{print NF}')
    if [[ "$field_count" -ne 5 ]]; then
        echo -e "${RED}[ERROR]${NC} Invalid cron schedule: '$schedule'"
        echo "  Use a shortcut (hourly, daily, weekly, monthly) or a 5-field cron expression."
        exit 1
    fi

    local cron_cmd="${expr} ${WEBSCAN_BIN} ${scan_path} ${extra_args} ${CRON_MARKER}"
    # Remove existing webscan cron for same path, then add new one
    local existing
    existing=$(crontab -l 2>/dev/null || true)
    local filtered
    filtered=$(echo "$existing" | grep -v "${CRON_MARKER}.*${scan_path}" || true)
    echo "${filtered}
${cron_cmd}" | sed '/^$/d' | crontab -

    echo ""
    echo -e "${GREEN}[OK]${NC} Cron job created successfully!"
    echo -e "  Schedule : ${BOLD}${expr}${NC} (${schedule})"
    echo -e "  Path     : ${BOLD}${scan_path}${NC}"
    [[ -n "$extra_args" ]] && echo -e "  Options  : ${extra_args}"
    echo -e "  Log dir  : ${LOG_DIR}"
    echo ""
    echo -e "  Manage: ${CYAN}webscan --list-cron${NC} | ${CYAN}webscan --remove-cron${NC}"
    exit 0
}

cron_list() {
    echo ""
    echo -e "${BOLD}Active webscan cron jobs:${NC}"
    echo ""
    local jobs
    jobs=$(crontab -l 2>/dev/null | grep "${CRON_MARKER}" || true)
    if [[ -z "$jobs" ]]; then
        echo "  No webscan cron jobs found."
    else
        echo "$jobs" | sed "s/ ${CRON_MARKER}//" | while IFS= read -r line; do
            echo "  $line"
        done
    fi
    echo ""
    exit 0
}

cron_remove() {
    local existing
    existing=$(crontab -l 2>/dev/null || true)
    local count
    count=$(echo "$existing" | grep -c "${CRON_MARKER}" || true)
    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}[INFO]${NC} No webscan cron jobs found."
        exit 0
    fi
    local filtered
    filtered=$(echo "$existing" | grep -v "${CRON_MARKER}" || true)
    echo "$filtered" | sed '/^$/d' | crontab -
    echo -e "${GREEN}[OK]${NC} Removed ${count} webscan cron job(s)."
    exit 0
}

# ── Argument Parsing ────────────────────────────────────────────────────────
NO_EMAIL=false
CRON_SCHEDULE=""

show_usage() {
    echo "Usage: webscan <path> [options]"
    echo ""
    echo "Arguments:"
    echo "  <path>                    Path to the website root directory"
    echo ""
    echo "Scan Options:"
    echo "  --webhook <url>           Send report to a webhook endpoint via POST"
    echo "  --api-key <key>           API key for webhook authentication"
    echo "  --email <address>         Recipient email for this scan"
    echo "  --no-email                Skip email notification for this scan"
    echo "  --background              Run scan in background (survives terminal close)"
    echo "  --cron <schedule>         Set up a cron job for recurring scans"
    echo "                            Shortcuts: hourly, daily, weekly, monthly"
    echo "                            Custom:    '0 2 * * *' (cron expression)"
    echo "  --remove-cron             Remove all webscan cron jobs"
    echo "  --list-cron               List active webscan cron jobs"
    echo ""
    echo "Configuration:"
    echo "  --set-email <address>     Save default email address"
    echo "  --enable-email            Enable email notifications by default"
    echo "  --disable-email           Disable email notifications by default"
    echo "  --set-webhook <url>       Save default webhook URL"
    echo "  --set-api-key <key>       Save default API key"
    echo "  --show-config             Show current configuration"
    echo "  --edit-config             Open config file in editor"
    echo "  --help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  webscan /var/www/html"
    echo "  webscan /var/www/html --email admin@site.com"
    echo "  webscan --set-email admin@site.com"
    echo "  webscan /var/www/html --background"
    echo "  webscan /var/www/html --cron daily"
    echo "  webscan /var/www/html --cron '0 2 * * 0' --email admin@site.com"
    echo "  webscan --list-cron"
    echo "  webscan --remove-cron"
    echo "  webscan --enable-email"
    echo "  webscan --show-config"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --webhook)       WEBHOOK_URL="$2"; shift 2 ;;
        --api-key)       API_KEY="$2"; shift 2 ;;
        --email)         NOTIFY_EMAIL="$2"; EMAIL_ENABLED=true; shift 2 ;;
        --no-email)      NO_EMAIL=true; shift ;;
        --background)    BACKGROUND=true; shift ;;
        --cron)          CRON_SCHEDULE="$2"; shift 2 ;;
        --list-cron)     cron_list ;;
        --remove-cron)   cron_remove ;;
        --set-email)     config_set "NOTIFY_EMAIL" "$2"; exit 0 ;;
        --enable-email)  config_set "EMAIL_ENABLED" "true"; exit 0 ;;
        --disable-email) config_set "EMAIL_ENABLED" "false"; exit 0 ;;
        --set-webhook)   config_set "WEBHOOK_URL" "$2"; exit 0 ;;
        --set-api-key)   config_set "API_KEY" "$2"; exit 0 ;;
        --show-config)   config_show ;;
        --edit-config)
            mkdir -p "$CONFIG_DIR"
            "${EDITOR:-nano}" "$CONFIG_FILE"
            exit 0 ;;
        --help|-h)       show_usage ;;
        -*)              echo "Unknown option: $1"; show_usage ;;
        *)
            if [[ -z "$SCAN_DIR" ]]; then
                SCAN_DIR="$1"
            fi
            shift ;;
    esac
done

# If --no-email flag was passed, clear email settings for this run
if [[ "$NO_EMAIL" == true ]]; then
    NOTIFY_EMAIL=""
    EMAIL_ENABLED=false
fi

# If email is not enabled, clear the email for this run
if [[ "$EMAIL_ENABLED" != "true" ]]; then
    NOTIFY_EMAIL=""
fi

SCAN_DIR="${SCAN_DIR:-.}"

# ── Handle --cron (set up cron job and exit) ─────────────────────────────────
if [[ -n "$CRON_SCHEDULE" ]]; then
    # Resolve scan dir to absolute path
    if [[ -d "$SCAN_DIR" ]]; then
        SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
    fi
    # Build extra args (forward email/webhook options to the cron command)
    EXTRA_ARGS=""
    [[ -n "$WEBHOOK_URL" ]] && EXTRA_ARGS+=" --webhook $WEBHOOK_URL"
    [[ -n "$API_KEY" ]] && EXTRA_ARGS+=" --api-key $API_KEY"
    [[ -n "$NOTIFY_EMAIL" ]] && EXTRA_ARGS+=" --email $NOTIFY_EMAIL"
    [[ "$NO_EMAIL" == true ]] && EXTRA_ARGS+=" --no-email"
    cron_add "$CRON_SCHEDULE" "$SCAN_DIR" $EXTRA_ARGS
fi

# ── Handle --background (re-launch self detached) ────────────────────────────
if [[ "$BACKGROUND" == true ]]; then
    # Resolve scan dir to absolute path
    if [[ -d "$SCAN_DIR" ]]; then
        SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
    fi
    mkdir -p "$LOG_DIR"
    BG_LOG="${LOG_DIR}/scan_${TIMESTAMP}.log"

    # Rebuild args without --background to avoid infinite loop
    BG_ARGS=("$SCAN_DIR")
    [[ -n "$WEBHOOK_URL" ]] && BG_ARGS+=(--webhook "$WEBHOOK_URL")
    [[ -n "$API_KEY" ]] && BG_ARGS+=(--api-key "$API_KEY")
    [[ -n "$NOTIFY_EMAIL" ]] && BG_ARGS+=(--email "$NOTIFY_EMAIL")
    [[ "$NO_EMAIL" == true ]] && BG_ARGS+=(--no-email)

    echo ""
    echo -e "${GREEN}[OK]${NC} Scan launched in background!"
    echo -e "  Log file : ${BOLD}${BG_LOG}${NC}"
    echo -e "  Monitor  : ${CYAN}tail -f ${BG_LOG}${NC}"
    echo ""
    nohup "$WEBSCAN_BIN" "${BG_ARGS[@]}" > "$BG_LOG" 2>&1 &
    disown
    exit 0
fi

# Detected frameworks (populated by detection phase)
declare -a FRAMEWORKS=()

# ── Cleanup ──────────────────────────────────────────────────────────────────
INTERRUPTED=false
cleanup() { 
    [[ -f "$FILE_LIST" ]] && rm -f "$FILE_LIST"
    rm -rf "$TEMP_DIR"
    if [[ "$INTERRUPTED" == true ]]; then
        err "Scan interrupted by user"
        exit 130
    fi
}
trap 'INTERRUPTED=true; cleanup' INT TERM
trap cleanup EXIT

# ── File List Cache ───────────────────────────────────────────────────────────
build_file_list() {
    log "Building file index..."
    FILE_LIST="$TEMP_DIR/all_files.txt"
    find "$SCAN_DIR" -type f -size -"$MAX_FILE_SIZE" 2>/dev/null | \
        grep -vE "$EXCLUDE_PATTERN" > "$FILE_LIST" || true
    local count=$(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)
    log "Indexed $count files for scanning"
}

# ── Security Score Calculation ────────────────────────────────────────────────
calculate_security_score() {
    local score=100
    local grade=""
    local grade_emoji=""
    
    # Point deductions
    score=$((score - CRITICAL * 25))
    score=$((score - HIGH * 15))
    score=$((score - MEDIUM * 5))
    score=$((score - LOW * 2))
    
    # Ensure score doesn't go below 0
    [[ $score -lt 0 ]] && score=0
    
    # Calculate grade
    if [[ $score -ge 90 ]]; then
        grade="A"; grade_emoji="🟢"
    elif [[ $score -ge 80 ]]; then
        grade="B"; grade_emoji="🟡"
    elif [[ $score -ge 70 ]]; then
        grade="C"; grade_emoji="🟠"
    elif [[ $score -ge 60 ]]; then
        grade="D"; grade_emoji="🔴"
    elif [[ $score -ge 50 ]]; then
        grade="E"; grade_emoji="⚫"
    else
        grade="F"; grade_emoji="⚫"
    fi
    
    echo "$score:$grade:$grade_emoji"
}

get_grade_description() {
    local grade="$1"
    case "$grade" in
        "A") echo "Excellent security posture. Continue regular monitoring and keep systems updated." ;;
        "B") echo "Good security with minor improvements needed. Address medium and low severity issues." ;;
        "C") echo "Fair security with notable vulnerabilities. Address high severity issues promptly." ;;
        "D") echo "Poor security with significant risks. Multiple high and critical issues require attention." ;;
        "E") echo "Critical security state. Severe vulnerabilities present. Immediate action required." ;;
        "F") echo "Failed security state. Critical compromise likely. Emergency security response needed." ;;
    esac
}

# ── Helper Functions ──────────────────────────────────────────────────────────
exclude_noise() { grep -vE "$EXCLUDE_PATTERN"; }

get_file_size() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        stat -f%z "$1" 2>/dev/null || echo 0
    else
        stat -c%s "$1" 2>/dev/null || echo 0
    fi
}

safe_grep() {
    local pattern="$1"
    shift
    $TIMEOUT_CMD grep -rnEi "$pattern" "$@" 2>/dev/null | exclude_noise | head -100 || true
}

safe_find() {
    local dir="$1"
    shift
    if [[ -f "$FILE_LIST" ]]; then
        # Use cached file list and filter by pattern
        cat "$FILE_LIST" | while read -r file; do
            [[ -f "$file" ]] && "$@" "$file" 2>/dev/null
        done | exclude_noise | head -100 || true
    else
        $TIMEOUT_CMD find "$dir" "$@" 2>/dev/null | exclude_noise | head -100 || true
    fi
}

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }

increment_issue() {
    local severity="$1"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    case "$severity" in
        critical) CRITICAL=$((CRITICAL + 1)) ;;
        high)     HIGH=$((HIGH + 1)) ;;
        medium)   MEDIUM=$((MEDIUM + 1)) ;;
        low)      LOW=$((LOW + 1)) ;;
        info)     INFO=$((INFO + 1)) ;;
    esac
}

severity_badge() {
    case "$1" in
        critical) echo "🔴 **CRITICAL**" ;;
        high)     echo "🟠 **HIGH**" ;;
        medium)   echo "🟡 **MEDIUM**" ;;
        low)      echo "🔵 **LOW**" ;;
        info)     echo "ℹ️ **INFO**" ;;
    esac
}

finding() {
    local severity="$1" title="$2" description="$3"
    local details="${4:-}" recommendation="${5:-}"

    increment_issue "$severity"

    cat >> "$REPORT_FILE" <<EOF

#### $(severity_badge "$severity") — $title

$description

EOF

    if [[ -n "$details" ]]; then
        cat >> "$REPORT_FILE" <<EOF
<details>
<summary>Details (click to expand)</summary>

\`\`\`
$details
\`\`\`

</details>

EOF
    fi

    if [[ -n "$recommendation" ]]; then
        cat >> "$REPORT_FILE" <<EOF
> **Recommendation:** $recommendation

EOF
    fi
}

has_framework() {
    local fw="$1"
    for f in "${FRAMEWORKS[@]}"; do
        [[ "$f" == "$fw" ]] && return 0
    done
    return 1
}

# ── Validate Input ───────────────────────────────────────────────────────────
if [[ ! -d "$SCAN_DIR" ]]; then
    err "Directory '$SCAN_DIR' does not exist."
    echo "Usage: sudo bash $0 /path/to/website"
    exit 1
fi

SCAN_DIR=$(cd "$SCAN_DIR" && pwd)

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          Universal Web Security Scanner v3.0                   ║"
echo "║          Malware · Vulnerability · Configuration Audit         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
log "Target directory : $SCAN_DIR"
log "Report file      : $REPORT_FILE"
log "Scan started     : $(date)"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0: FRAMEWORK DETECTION
# ══════════════════════════════════════════════════════════════════════════════
log "Detecting frameworks and CMS..."

# WordPress
[[ -f "$SCAN_DIR/wp-config.php" || -f "$SCAN_DIR/wp-login.php" ]] && FRAMEWORKS+=("wordpress")

# Laravel
[[ -f "$SCAN_DIR/artisan" && -d "$SCAN_DIR/app" && -d "$SCAN_DIR/bootstrap" ]] && FRAMEWORKS+=("laravel")

# Drupal
[[ -f "$SCAN_DIR/core/lib/Drupal.php" || -f "$SCAN_DIR/sites/default/settings.php" ]] && FRAMEWORKS+=("drupal")

# Joomla
[[ -f "$SCAN_DIR/configuration.php" && -d "$SCAN_DIR/administrator" ]] && FRAMEWORKS+=("joomla")

# Magento
[[ -f "$SCAN_DIR/bin/magento" || -f "$SCAN_DIR/app/etc/env.php" ]] && FRAMEWORKS+=("magento")

# CodeIgniter
[[ -d "$SCAN_DIR/application" && -d "$SCAN_DIR/system" && -f "$SCAN_DIR/index.php" ]] && FRAMEWORKS+=("codeigniter")

# Symfony
[[ -f "$SCAN_DIR/symfony.lock" || -f "$SCAN_DIR/config/bundles.php" ]] && FRAMEWORKS+=("symfony")

# CakePHP
[[ -f "$SCAN_DIR/config/app.php" && -d "$SCAN_DIR/src/Controller" ]] && FRAMEWORKS+=("cakephp")

# Node.js / Express / Next.js
if [[ -f "$SCAN_DIR/package.json" ]]; then
    FRAMEWORKS+=("nodejs")
    grep -q '"next"' "$SCAN_DIR/package.json" 2>/dev/null && FRAMEWORKS+=("nextjs")
    grep -q '"express"' "$SCAN_DIR/package.json" 2>/dev/null && FRAMEWORKS+=("express")
fi

# Django
[[ -f "$SCAN_DIR/manage.py" ]] && grep -q "django" "$SCAN_DIR/manage.py" 2>/dev/null && FRAMEWORKS+=("django")

# Flask
grep -rql "from flask import\|from flask_" "$SCAN_DIR"/*.py 2>/dev/null && FRAMEWORKS+=("flask")

# Ruby on Rails
[[ -f "$SCAN_DIR/Gemfile" ]] && grep -q "rails" "$SCAN_DIR/Gemfile" 2>/dev/null && FRAMEWORKS+=("rails")

# Static site / generic
[[ ${#FRAMEWORKS[@]} -eq 0 ]] && FRAMEWORKS+=("generic")

# Remove duplicates
FRAMEWORKS=($(printf '%s\n' "${FRAMEWORKS[@]}" | sort -u))

for fw in "${FRAMEWORKS[@]}"; do
    ok "Detected: $fw"
done
echo ""

# Determine primary language
HAS_PHP=false; HAS_JS=false; HAS_PYTHON=false; HAS_RUBY=false
find "$SCAN_DIR" -maxdepth 3 -name "*.php" -type f 2>/dev/null | head -1 | grep -q . && HAS_PHP=true
find "$SCAN_DIR" -maxdepth 3 -name "*.js" -type f 2>/dev/null | head -1 | grep -q . && HAS_JS=true
find "$SCAN_DIR" -maxdepth 3 -name "*.py" -type f 2>/dev/null | head -1 | grep -q . && HAS_PYTHON=true
find "$SCAN_DIR" -maxdepth 3 -name "*.rb" -type f 2>/dev/null | head -1 | grep -q . && HAS_RUBY=true

# Build file list cache for faster scanning
build_file_list

# ══════════════════════════════════════════════════════════════════════════════
# INITIALIZE REPORT
# ══════════════════════════════════════════════════════════════════════════════
# Start timer for scan duration
SCAN_START_TIME=$(date +%s)

# Check for scan timeout
check_timeout() {
    local current_time=$(date +%s)
    local elapsed=$((current_time - SCAN_START_TIME))
    if [[ $elapsed -gt $SCAN_TIMEOUT ]]; then
        err "Scan timeout reached ($SCAN_TIMEOUT seconds)"
        return 1
    fi
    return 0
}
FW_LIST=$(IFS=', '; echo "${FRAMEWORKS[*]}")

cat > "$REPORT_FILE" <<EOF
# 🛡️ Website Security Scan Report

| Field | Value |
|-------|-------|
| **Scan Target** | \`$SCAN_DIR\` |
| **Scan Date** | $(date '+%B %d, %Y at %H:%M:%S %Z') |
| **Hostname** | $(hostname 2>/dev/null || echo "N/A") |
| **Detected Framework(s)** | $FW_LIST |
| **Scanner** | Universal Web Security Scanner v3.0 |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Malware & Backdoor Detection](#1-malware--backdoor-detection)
3. [Suspicious Files & Code Patterns](#2-suspicious-files--code-patterns)
4. [Obfuscated & Encoded Code](#3-obfuscated--encoded-code)
5. [File Integrity & Anomalies](#4-file-integrity--anomalies)
6. [Framework-Specific Audit](#5-framework-specific-audit)
7. [Dependency & Supply Chain Risks](#6-dependency--supply-chain-risks)
8. [File Permissions Audit](#7-file-permissions-audit)
9. [Server Configuration Issues](#8-server-configuration-issues)
10. [Secrets & Credential Exposure](#9-secrets--credential-exposure)
11. [Network & Access Security](#10-network--access-security)
12. [Recently Modified Files](#11-recently-modified-files)
13. [Recommendations](#recommendations)

---

EOF


# ██████████████████████████████████████████████████████████████████████████████
#                  UNIVERSAL SCANS (ALL FRAMEWORKS)
# ██████████████████████████████████████████████████████████████████████████████


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: MALWARE & BACKDOOR DETECTION
# ══════════════════════════════════════════════════════════════════════════════
log "Scanning for malware signatures & backdoors..."

cat >> "$REPORT_FILE" <<'EOF'
## 1. Malware & Backdoor Detection

Scanning for known malware patterns, web shells, backdoors, and malicious code injections.

EOF

# ── 1a. Known Web Shells ─────────────────────────────────────────────────────
WEBSHELL_PATTERNS=(
    'r57shell' 'c99shell' 'c100.php' 'WSO\s' 'b374k' 'FilesMan'
    'ALFA_DATA' 'alfashell' 'Meterpreter' 'phpspy' 'GIF89a.*<\?php'
    'AnonymousFox' 'IndoXploit' 'FLAVIOPEREIRA' 'marlboro' 'k2ll33d'
    'Dx2023' 'DEVELOPER FLAVOR' 'web.*shell' 'php.*shell.*tool'
    'Weevely' 'China\s*Chopper' 'ice.*scorpion' 'behinder'
    'godzilla.*shell' 'JspSpy' 'AntSword'
)
WEBSHELL_REGEX=$(IFS='|'; echo "${WEBSHELL_PATTERNS[*]}")

WEBSHELL_RESULTS=$(grep -rlEi "$WEBSHELL_REGEX" "$SCAN_DIR" \
    --include="*.php" --include="*.php5" --include="*.phtml" --include="*.pht" \
    --include="*.suspected" --include="*.jsp" --include="*.jspx" \
    --include="*.asp" --include="*.aspx" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" | head -50 || true)

if [[ -n "$WEBSHELL_RESULTS" ]]; then
    finding "critical" "Known Web Shell Signatures Detected" \
        "Files matching known web shell signatures were found. These are almost certainly malicious." \
        "$WEBSHELL_RESULTS" \
        "Immediately quarantine or delete these files. Investigate how they were uploaded."
else
    echo "✅ No known web shell signatures found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 1b. PHP Backdoor Functions ──────────────────────────────────────────────
if $HAS_PHP; then
    log "Checking for PHP backdoor patterns..."

    BACKDOOR_PATTERNS=(
        'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
        'eval\s*\(\s*base64_decode'
        'eval\s*\(\s*gzinflate'
        'eval\s*\(\s*gzuncompress'
        'eval\s*\(\s*str_rot13'
        'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
        'preg_replace\s*\(.*\/e\s*["\x27]'
        'create_function\s*\('
        'call_user_func\s*\(\s*\$_(GET|POST|REQUEST)'
        'array_map\s*\(\s*\$_(GET|POST|REQUEST)'
        'array_filter\s*\(\s*\$_(GET|POST|REQUEST)'
        'usort\s*\(.*\$_(GET|POST|REQUEST)'
        '\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\[.*\]\s*;\s*@?\$\w+\s*\('
        'passthru\s*\(\s*\$_(GET|POST|REQUEST)'
        'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)'
        'system\s*\(\s*\$_(GET|POST|REQUEST)'
        'exec\s*\(\s*\$_(GET|POST|REQUEST)'
        'popen\s*\(\s*\$_(GET|POST|REQUEST)'
        'proc_open\s*\(\s*\$_(GET|POST|REQUEST)'
        'pcntl_exec\s*\('
        'file_put_contents\s*\(.*\$_(GET|POST|REQUEST)'
        'fwrite\s*\(.*\$_(GET|POST|REQUEST)'
    )

    BACKDOOR_REGEX=$(IFS='|'; echo "${BACKDOOR_PATTERNS[*]}")
    BACKDOOR_RESULTS=$(grep -rnEi "$BACKDOOR_REGEX" "$SCAN_DIR" \
        --include="*.php" --include="*.php5" --include="*.phtml" --include="*.inc" \
        2>/dev/null | grep -v "node_modules\|vendor/" | head -100 || true)

    if [[ -n "$BACKDOOR_RESULTS" ]]; then
        finding "critical" "PHP Backdoor Function Patterns Detected" \
            "Code patterns commonly used in PHP backdoors were found, allowing remote code execution." \
            "$BACKDOOR_RESULTS" \
            "Review each file carefully. Remove any that contain backdoor code."
    else
        echo "✅ No PHP backdoor patterns found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 1c. Python Backdoor / Reverse Shell Patterns ────────────────────────────
if $HAS_PYTHON; then
    log "Checking for Python backdoor patterns..."

    PY_BACKDOOR_PATTERNS=(
        'import\s+subprocess.*shell\s*=\s*True'
        'os\.system\s*\(.*request\.'
        'os\.popen\s*\(.*request\.'
        'subprocess\.call\s*\(.*request\.'
        'exec\s*\(\s*request\.(GET|POST|args|form|data)'
        'eval\s*\(\s*request\.(GET|POST|args|form|data)'
        '__import__\s*\(\s*["\x27]os["\x27]\s*\)\.system'
        'socket\.socket.*connect\s*\('
        'pty\.spawn'
        'pickle\.loads\s*\(.*request'
        'yaml\.load\s*\(.*request'
        'marshal\.loads'
    )

    PY_BACKDOOR_REGEX=$(IFS='|'; echo "${PY_BACKDOOR_PATTERNS[*]}")
    PY_RESULTS=$(grep -rnEi "$PY_BACKDOOR_REGEX" "$SCAN_DIR" \
        --include="*.py" 2>/dev/null | grep -v "node_modules\|venv/\|\.git/\|__pycache__" | head -50 || true)

    if [[ -n "$PY_RESULTS" ]]; then
        finding "critical" "Python Backdoor / Reverse Shell Patterns" \
            "Dangerous Python code patterns were found that could allow remote code execution." \
            "$PY_RESULTS" \
            "Review these files. Patterns like eval(request.data) or os.system(request.args) are critical vulnerabilities."
    else
        echo "✅ No Python backdoor patterns found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 1d. Node.js Backdoor Patterns ───────────────────────────────────────────
if $HAS_JS; then
    log "Checking for Node.js backdoor patterns..."

    JS_BACKDOOR_PATTERNS=(
        'child_process.*exec\s*\(\s*req\.(body|query|params)'
        'child_process.*spawn\s*\(\s*req\.(body|query|params)'
        'eval\s*\(\s*req\.(body|query|params)'
        'new\s+Function\s*\(\s*req\.(body|query|params)'
        'vm\.runInNewContext\s*\(.*req\.'
        'require\s*\(\s*["\x27]child_process["\x27]\s*\).*exec\s*\(\s*req'
        'process\.binding\s*\('
        'Buffer\.from\s*\(.*["\x27]base64["\x27]\s*\).*eval'
    )

    JS_BACKDOOR_REGEX=$(IFS='|'; echo "${JS_BACKDOOR_PATTERNS[*]}")
    JS_RESULTS=$(grep -rnEi "$JS_BACKDOOR_REGEX" "$SCAN_DIR" \
        --include="*.js" --include="*.mjs" --include="*.ts" \
        2>/dev/null | grep -v "node_modules\|\.next/\|dist/\|build/" | head -50 || true)

    if [[ -n "$JS_RESULTS" ]]; then
        finding "critical" "Node.js Backdoor / Command Injection Patterns" \
            "Dangerous Node.js code patterns were found that could allow remote code execution." \
            "$JS_RESULTS" \
            "Never pass user input directly to child_process, eval(), or new Function(). Sanitize all inputs."
    else
        echo "✅ No Node.js backdoor patterns found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 1e. Malicious Iframes & Script Injections (universal) ───────────────────
log "Checking for malicious iframes & injections..."

INJECT_PATTERNS=(
    '<iframe[^>]*style\s*=\s*["\x27][^"]*display\s*:\s*none'
    '<iframe[^>]*width\s*=\s*["\x270]["\x27]'
    '<iframe[^>]*height\s*=\s*["\x270]["\x27]'
    '<script[^>]*src\s*=\s*["\x27]https?://[^/]*\.(xyz|tk|ml|ga|cf|top|buzz|click|gq)/'
    'document\.write\s*\(\s*unescape'
    'document\.write\s*\(\s*String\.fromCharCode'
    'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k'
    '<script[^>]*>.*var\s+_0x[a-f0-9]+'
    'onmouseover\s*=\s*["\x27]\s*eval'
    'onerror\s*=\s*["\x27]\s*eval'
)

INJECT_REGEX=$(IFS='|'; echo "${INJECT_PATTERNS[*]}")
INJECT_RESULTS=$(grep -rnEi "$INJECT_REGEX" "$SCAN_DIR" \
    --include="*.php" --include="*.html" --include="*.htm" --include="*.js" \
    --include="*.tpl" --include="*.blade.php" --include="*.twig" --include="*.ejs" \
    --include="*.pug" --include="*.hbs" --include="*.erb" --include="*.jinja2" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" | head -50 || true)

if [[ -n "$INJECT_RESULTS" ]]; then
    finding "high" "Malicious Script Injections / Hidden Iframes" \
        "Hidden iframes or suspicious script injections were found." \
        "$INJECT_RESULTS" \
        "Remove injected code. Investigate the entry point — often a compromised plugin, dependency, or stolen credentials."
else
    echo "✅ No malicious iframe or script injections found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 1f. Crypto Miners ───────────────────────────────────────────────────────
log "Checking for cryptocurrency miners..."

MINER_PATTERNS=(
    'coinhive' 'CoinImp' 'cryptonight' 'coin-hive' 'jsecoin'
    'cryptoloot' 'minero\.cc' 'webminepool' 'miner\.start'
    'stratum\+tcp' 'MoneroOcean'
)
MINER_REGEX=$(IFS='|'; echo "${MINER_PATTERNS[*]}")
MINER_RESULTS=$(grep -rlEi "$MINER_REGEX" "$SCAN_DIR" \
    --include="*.php" --include="*.js" --include="*.html" --include="*.py" --include="*.rb" \
    2>/dev/null | grep -v "node_modules\|vendor/" | head -20 || true)

if [[ -n "$MINER_RESULTS" ]]; then
    finding "critical" "Cryptocurrency Miner Detected" \
        "Files referencing known cryptocurrency mining scripts were found." \
        "$MINER_RESULTS" \
        "Remove the mining code immediately. This hijacks visitors' CPU resources."
else
    echo "✅ No cryptocurrency miners found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 1g. SEO Spam / Pharma Hack ──────────────────────────────────────────────
log "Checking for SEO spam / pharma hacks..."

SPAM_PATTERNS=(
    'viagra|cialis|levitra|kamagra'
    'buy.*cheap.*online'
    'poker.*online.*casino'
    'display:none.*<a.*href'
    'position:absolute.*left:-[0-9]{4,}'
    'cloaking.*googlebot'
)
SPAM_REGEX=$(IFS='|'; echo "${SPAM_PATTERNS[*]}")
SPAM_RESULTS=$(grep -rlEi "$SPAM_REGEX" "$SCAN_DIR" \
    --include="*.php" --include="*.html" --include="*.htm" --include="*.tpl" \
    --include="*.blade.php" --include="*.twig" --include="*.erb" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" | head -30 || true)

if [[ -n "$SPAM_RESULTS" ]]; then
    finding "high" "SEO Spam / Pharma Hack Indicators" \
        "Files containing pharmaceutical spam or SEO injection patterns were found." \
        "$SPAM_RESULTS" \
        "Clean injected content and investigate the entry point."
else
    echo "✅ No SEO spam indicators found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SUSPICIOUS FILES & CODE PATTERNS
# ══════════════════════════════════════════════════════════════════════════════
log "Scanning for suspicious files..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 2. Suspicious Files & Code Patterns

Detecting files in unexpected locations, suspicious names, and dangerous code patterns.

EOF

# ── 2a. Executable files in upload/media directories ─────────────────────────
UPLOAD_DIRS=(
    "uploads" "upload" "media" "files" "assets/uploads"
    "storage/app/public"   # Laravel
    "sites/default/files"  # Drupal
    "images" "tmp" "temp"
    "pub/media"            # Magento
)

UPLOADS_EXEC=""
for UD in "${UPLOAD_DIRS[@]}"; do
    FULL_PATH="$SCAN_DIR/$UD"
    [[ ! -d "$FULL_PATH" ]] && continue
    FOUND=$(find "$FULL_PATH" -type f \( \
        -name "*.php" -o -name "*.php5" -o -name "*.phtml" -o -name "*.pht" \
        -o -name "*.py" -o -name "*.pl" -o -name "*.cgi" -o -name "*.sh" \
        -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \
        \) 2>/dev/null || true)
    [[ -n "$FOUND" ]] && UPLOADS_EXEC+="$FOUND"$'\n'
done

if [[ -n "$UPLOADS_EXEC" ]]; then
    finding "critical" "Executable Files in Upload/Media Directories" \
        "Server-side executable files were found in directories meant for user uploads. These are very likely backdoors." \
        "$UPLOADS_EXEC" \
        "Delete these files immediately. Configure the server to block execution of scripts in upload directories."
else
    echo "✅ No executable files found in upload directories." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 2b. Suspicious filenames (universal) ─────────────────────────────────────
SUSPICIOUS_NAMES=$(find "$SCAN_DIR" -type f \( \
    -name "*.php.suspected" -o -name "*.php.bak" -o -name "*.php.old" \
    -o -name "*.php.swp" -o -name "*.py.bak" -o -name "*.js.bak" \
    -o -name "shell*.php" -o -name "cmd.php" -o -name "cmd*.php" \
    -o -name "cpanel.php" -o -name "sql.php" -o -name "ssh.php" \
    -o -name "upload.php" -o -name "uploader.php" -o -name "filemanager.php" \
    -o -name "adminer.php" -o -name "phpmyadmin.php" \
    -o -name "wp-vcd.php" -o -name "class.theme-modules.php" \
    -o -name "satan*.php" -o -name "vuln.php" -o -name "hack*.php" \
    -o -name "mailer.php" -o -name "leafmailer.php" \
    -o -name "fox.php" -o -name "lock360.php" -o -name "radio.php" \
    -o -name "*.suspected" -o -name "0*.php" \
    -o -iname "*backdoor*" -o -iname "*exploit*" -o -iname "*rootkit*" \
    \) 2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|test" | head -50 || true)

if [[ -n "$SUSPICIOUS_NAMES" ]]; then
    finding "high" "Files with Suspicious Names" \
        "Files with names commonly associated with malware or hacking tools were found." \
        "$SUSPICIOUS_NAMES" \
        "Review each file. Delete any that are not part of legitimate code."
else
    echo "✅ No suspiciously named files found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 2c. Polyglot files (PHP/scripts hidden in images) ───────────────────────
log "Checking for code hidden in image files..."

POLYGLOT_FILES=""
while IFS= read -r f; do
    if file "$f" 2>/dev/null | grep -qi "php\|ascii\|text\|script"; then
        POLYGLOT_FILES+="$f"$'\n'
    fi
done < <(find "$SCAN_DIR" -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \
    -o -name "*.gif" -o -name "*.ico" -o -name "*.bmp" -o -name "*.svg" \) \
    -size +0c -size -500k 2>/dev/null | grep -v "node_modules\|vendor/" | head -300)

if [[ -n "$POLYGLOT_FILES" ]]; then
    finding "critical" "Script Code Hidden in Image/Media Files" \
        "Image files containing executable code were detected — a classic technique to hide backdoors." \
        "$POLYGLOT_FILES" \
        "Delete these files. Audit upload mechanisms to prevent this."
else
    echo "✅ No code hidden in image files." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 2d. Large single-line files (obfuscated) ────────────────────────────────
LARGELINE_FILES=""
while IFS= read -r f; do
    LINES=$(wc -l < "$f" 2>/dev/null || echo 0)
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
    if [[ "$LINES" -lt 5 && "$SIZE" -gt 5000 ]]; then
        LARGELINE_FILES+="$f (${SIZE} bytes, ${LINES} lines)"$'\n'
    fi
done < <(find "$SCAN_DIR" -type f \( -name "*.php" -o -name "*.js" \) -size +5k \
    2>/dev/null | grep -v "node_modules\|vendor/\|dist/\|build/\|\.min\." | head -200)

if [[ -n "$LARGELINE_FILES" ]]; then
    finding "high" "Large Single-Line Files (Likely Obfuscated)" \
        "Files with very few lines but large size indicate obfuscated malware or injected code." \
        "$LARGELINE_FILES" \
        "Inspect these files manually. Legitimate source files rarely consist of a single long line (minified files excluded)."
else
    echo "✅ No suspicious single-line files found." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 2e. SQL Injection patterns in code ───────────────────────────────────────
log "Checking for SQL injection vulnerabilities in code..."

SQLI_PATTERNS=()

if $HAS_PHP; then
    SQLI_PATTERNS+=(
        'query\s*\(\s*["\x27].*\$_(GET|POST|REQUEST|COOKIE)'
        'mysql_query\s*\(\s*["\x27].*\$_(GET|POST|REQUEST)'
        'mysqli_query\s*\(.*\$_(GET|POST|REQUEST)'
        '\->query\s*\(\s*["\x27].*\.\s*\$_(GET|POST|REQUEST)'
    )
fi

if $HAS_PYTHON; then
    SQLI_PATTERNS+=(
        'execute\s*\(\s*["\x27].*%s.*%\s*\(\s*request\.'
        'execute\s*\(\s*f["\x27].*\{request\.'
        'execute\s*\(.*\.format\s*\(.*request\.'
    )
fi

if $HAS_JS; then
    SQLI_PATTERNS+=(
        'query\s*\(\s*`.*\$\{req\.(body|query|params)'
        'query\s*\(\s*["\x27].*\+\s*req\.(body|query|params)'
    )
fi

if [[ ${#SQLI_PATTERNS[@]} -gt 0 ]]; then
    SQLI_REGEX=$(IFS='|'; echo "${SQLI_PATTERNS[*]}")
    SQLI_RESULTS=$(grep -rnEi "$SQLI_REGEX" "$SCAN_DIR" \
        --include="*.php" --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" \
        2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/" | head -30 || true)

    if [[ -n "$SQLI_RESULTS" ]]; then
        finding "critical" "Potential SQL Injection Vulnerabilities" \
            "Code patterns where user input is directly concatenated into SQL queries without parameterization." \
            "$SQLI_RESULTS" \
            "Use prepared statements / parameterized queries. NEVER concatenate user input into SQL strings."
    else
        echo "✅ No obvious SQL injection patterns found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 2f. XSS patterns in code ────────────────────────────────────────────────
log "Checking for XSS vulnerabilities..."

XSS_PATTERNS=()

if $HAS_PHP; then
    XSS_PATTERNS+=(
        'echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)\['
        'print\s+\$_(GET|POST|REQUEST)\['
        '<?=\s*\$_(GET|POST|REQUEST)\['
    )
fi

if $HAS_PYTHON; then
    XSS_PATTERNS+=(
        'return\s+HttpResponse\s*\(\s*request\.(GET|POST)'
        'mark_safe\s*\(\s*request\.'
        'Markup\s*\(\s*request\.'
    )
fi

if [[ ${#XSS_PATTERNS[@]} -gt 0 ]]; then
    XSS_REGEX=$(IFS='|'; echo "${XSS_PATTERNS[*]}")
    XSS_RESULTS=$(grep -rnEi "$XSS_REGEX" "$SCAN_DIR" \
        --include="*.php" --include="*.py" --include="*.erb" \
        2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/" | head -30 || true)

    if [[ -n "$XSS_RESULTS" ]]; then
        finding "high" "Potential Cross-Site Scripting (XSS) Vulnerabilities" \
            "User input appears to be echoed directly without proper escaping or sanitization." \
            "$XSS_RESULTS" \
            "Always escape output. Use htmlspecialchars() in PHP, escape filters in templates, or framework sanitizers."
    else
        echo "✅ No obvious XSS patterns found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: OBFUSCATED & ENCODED CODE
# ══════════════════════════════════════════════════════════════════════════════
log "Scanning for obfuscated & encoded code..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 3. Obfuscated & Encoded Code

Detecting base64 encoding, hex encoding, string obfuscation, and packer patterns.

EOF

# ── 3a. Suspicious base64 usage (PHP) ────────────────────────────────────────
if $HAS_PHP; then
    B64_PATTERNS=(
        'eval\s*\(\s*base64_decode\s*\('
        'base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
        '\$\w+\s*=\s*base64_decode\s*\(["\x27][A-Za-z0-9+/=]{100,}'
        'base64_decode\s*\(\s*gzinflate'
        'base64_decode\s*\(\s*str_rot13'
    )
    B64_REGEX=$(IFS='|'; echo "${B64_PATTERNS[*]}")
    B64_RESULTS=$(grep -rnEi "$B64_REGEX" "$SCAN_DIR" \
        --include="*.php" --include="*.inc" \
        2>/dev/null | grep -v "node_modules\|vendor/" | head -50 || true)

    if [[ -n "$B64_RESULTS" ]]; then
        finding "high" "Suspicious Base64 Encoding (PHP)" \
            "Base64-encoded code execution patterns were found. Legitimate code rarely uses eval(base64_decode())." \
            "$B64_RESULTS" \
            "Decode the content to inspect it. Remove if malicious."
    else
        echo "✅ No suspicious PHP base64 patterns." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 3b. Suspicious base64/eval in JS ────────────────────────────────────────
if $HAS_JS; then
    JS_OBFUSC_PATTERNS=(
        'eval\s*\(\s*atob\s*\('
        'eval\s*\(\s*Buffer\.from\s*\(.*base64'
        'Function\s*\(\s*atob\s*\('
        'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k'
        'var\s+_0x[a-f0-9]+\s*='
    )
    JS_OBFUSC_REGEX=$(IFS='|'; echo "${JS_OBFUSC_PATTERNS[*]}")
    JS_OBFUSC_RESULTS=$(grep -rnEi "$JS_OBFUSC_REGEX" "$SCAN_DIR" \
        --include="*.js" --include="*.mjs" 2>/dev/null | \
        grep -v "node_modules\|\.min\.js\|dist/\|build/" | head -30 || true)

    if [[ -n "$JS_OBFUSC_RESULTS" ]]; then
        finding "high" "Obfuscated JavaScript Detected" \
            "JavaScript files with heavy obfuscation patterns were found (excluding minified files)." \
            "$JS_OBFUSC_RESULTS" \
            "Deobfuscate and review. Malicious JS often uses eval(atob()) or _0x variable patterns."
    else
        echo "✅ No obfuscated JavaScript found." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi

# ── 3c. Hex-encoded strings ─────────────────────────────────────────────────
HEX_RESULTS=$(grep -rnP '\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}' "$SCAN_DIR" \
    --include="*.php" --include="*.js" --include="*.py" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.min\." | head -30 || true)

if [[ -n "$HEX_RESULTS" ]]; then
    finding "medium" "Long Hex-Encoded Strings Detected" \
        "Long hex-encoded string sequences may hide malicious code." \
        "$HEX_RESULTS" \
        "Decode and review. Compare against original source files."
else
    echo "✅ No suspicious hex-encoded strings." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 3d. PHP code obfuscation techniques ─────────────────────────────────────
if $HAS_PHP; then
    OBFUSC_PATTERNS=(
        '\$\w+\s*\(\s*\$\w+\s*\(\s*\$\w+\s*\('
        'chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr\s*\(\s*[0-9]+\s*\)\s*\.\s*chr'
        '\$GLOBALS\[\s*["\x27]\w+["\x27]\s*\]\s*=.*\$GLOBALS'
        'extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
        'ionCube|SourceGuardian|Zend Optimizer|phpSHIELD'
    )
    OBFUSC_REGEX=$(IFS='|'; echo "${OBFUSC_PATTERNS[*]}")
    OBFUSC_RESULTS=$(grep -rnEi "$OBFUSC_REGEX" "$SCAN_DIR" \
        --include="*.php" 2>/dev/null | grep -v "node_modules\|vendor/" | head -30 || true)

    if [[ -n "$OBFUSC_RESULTS" ]]; then
        finding "high" "PHP Code Obfuscation Patterns" \
            "Advanced obfuscation techniques or commercial encoders were found." \
            "$OBFUSC_RESULTS" \
            "These patterns are rarely used in legitimate open-source code. Review carefully."
    else
        echo "✅ No PHP obfuscation patterns." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: FILE INTEGRITY & ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════
log "Checking file integrity..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 4. File Integrity & Anomalies

Checking for recently created files, symlink attacks, and anomalous patterns.

EOF

# ── 4a. Recently created executable files (last 7 days) ─────────────────────
RECENT_EXEC=$(find "$SCAN_DIR" -type f \( \
    -name "*.php" -o -name "*.js" -o -name "*.py" -o -name "*.rb" \
    -o -name "*.pl" -o -name "*.cgi" -o -name "*.sh" \
    \) -ctime -7 2>/dev/null | \
    grep -v "node_modules\|vendor/\|\.git/\|cache\|venv/\|__pycache__\|dist/\|build/" | head -50 || true)

if [[ -n "$RECENT_EXEC" ]]; then
    finding "medium" "Executable Files Created/Changed in Last 7 Days" \
        "These executable files were recently created or modified. Review if unexpected." \
        "$RECENT_EXEC" \
        "Cross-reference with recent deployments. Unexpected new files may indicate compromise."
else
    echo "✅ No newly created executable files in the last 7 days." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# ── 4b. Symlinks pointing outside web root ───────────────────────────────────
SYMLINKS=$(find "$SCAN_DIR" -type l 2>/dev/null | head -20 || true)
if [[ -n "$SYMLINKS" ]]; then
    EXTERNAL_SYMLINKS=""
    while IFS= read -r link; do
        TARGET=$(readlink -f "$link" 2>/dev/null || echo "")
        if [[ -n "$TARGET" && "$TARGET" != "$SCAN_DIR"* ]]; then
            EXTERNAL_SYMLINKS+="$link -> $TARGET"$'\n'
        fi
    done <<< "$SYMLINKS"

    if [[ -n "$EXTERNAL_SYMLINKS" ]]; then
        finding "high" "Symlinks Pointing Outside Web Root" \
            "Symbolic links pointing outside the web root could expose sensitive system files." \
            "$EXTERNAL_SYMLINKS" \
            "Remove symlinks that point outside the web root unless intentionally configured."
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: FRAMEWORK-SPECIFIC AUDIT
# ══════════════════════════════════════════════════════════════════════════════
log "Running framework-specific audits..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 5. Framework-Specific Audit

Configuration and security checks tailored to the detected framework(s).

EOF

# ┌─────────────────────────────────────────────────────────────────────┐
# │ WORDPRESS                                                          │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "wordpress"; then
    echo "### WordPress Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    WP_CONFIG="$SCAN_DIR/wp-config.php"

    WP_VER_FILE="$SCAN_DIR/wp-includes/version.php"
    if [[ -f "$WP_VER_FILE" ]]; then
        WP_VERSION=$(grep '^\$wp_version\s*=' "$WP_VER_FILE" 2>/dev/null | sed "s/.*'\(.*\)'.*/\1/" || echo "unknown")
        echo "**WordPress Version:** \`$WP_VERSION\`" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        WP_MAJOR=$(echo "$WP_VERSION" | cut -d. -f1 | tr -dc '0-9')
        WP_MINOR=$(echo "$WP_VERSION" | cut -d. -f2 | tr -dc '0-9')
        WP_MAJOR=${WP_MAJOR:-0}; WP_MINOR=${WP_MINOR:-0}
        if [[ "$WP_MAJOR" -lt 6 ]] || { [[ "$WP_MAJOR" -eq 6 ]] && [[ "$WP_MINOR" -lt 4 ]]; }; then
            finding "high" "Outdated WordPress Version ($WP_VERSION)" \
                "This WordPress version may contain known security vulnerabilities." \
                "" \
                "Update to the latest WordPress version. Back up the database first."
        fi
    fi

    if [[ -f "$WP_CONFIG" ]]; then
        # Debug mode
        if grep -qEi "define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
            finding "high" "WordPress Debug Mode Enabled" \
                "WP_DEBUG is true — error information is exposed." \
                "" \
                "Set WP_DEBUG to false in production."
        fi

        # File editor
        if ! grep -qEi "define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
            finding "medium" "WordPress File Editor Not Disabled" \
                "The built-in file editor allows admin users to edit PHP files from the dashboard." \
                "" \
                "Add \`define('DISALLOW_FILE_EDIT', true);\` to wp-config.php."
        fi

        # Security keys
        DEFAULT_KEYS=$(grep -cE "put your unique phrase here" "$WP_CONFIG" 2>/dev/null | head -1)
        DEFAULT_KEYS=${DEFAULT_KEYS:-0}
        if [[ "$DEFAULT_KEYS" -gt 0 ]]; then
            finding "critical" "Default WordPress Security Keys" \
                "Security keys are still default — session security is severely weakened." \
                "" \
                "Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/"
        fi

        # Table prefix
        if grep -qEi "\\\$table_prefix\s*=\s*['\"]wp_['\"]" "$WP_CONFIG" 2>/dev/null; then
            finding "low" "Default Database Table Prefix (wp_)" \
                "Default prefix makes SQL injection attacks easier to target." \
                "" \
                "Consider a custom table prefix."
        fi

        # SSL
        if ! grep -qEi "define\s*\(\s*['\"]FORCE_SSL_ADMIN['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
            finding "medium" "SSL Not Forced for WordPress Admin" \
                "FORCE_SSL_ADMIN is not enabled." \
                "" \
                "Add \`define('FORCE_SSL_ADMIN', true);\`"
        fi

        # DB root
        DB_USER=$(grep "DB_USER" "$WP_CONFIG" 2>/dev/null | sed "s/.*['\"]DB_USER['\"].*['\"]\\(.*\\)['\"].*/\\1/" | head -1 || echo "")
        if [[ "$DB_USER" == "root" ]]; then
            finding "critical" "WordPress Using Root Database User" \
                "Connecting as root is extremely dangerous." \
                "" \
                "Create a dedicated database user."
        fi
    fi

    # Plugin inventory
    PLUGIN_DIR="$SCAN_DIR/wp-content/plugins"
    if [[ -d "$PLUGIN_DIR" ]]; then
        echo "#### Installed Plugins" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "| Plugin | Version | Notes |" >> "$REPORT_FILE"
        echo "|--------|---------|-------|" >> "$REPORT_FILE"

        PC=0
        for PD in "$PLUGIN_DIR"/*/; do
            [[ ! -d "$PD" ]] && continue
            PN=$(basename "$PD"); PC=$((PC + 1)); PV="Unknown"
            for PF in "$PD"*.php; do
                [[ -f "$PF" ]] || continue
                V=$(grep -i "Version:" "$PF" 2>/dev/null | head -1 | sed 's/.*Version:\s*//i' | tr -d '[:space:]')
                [[ -n "$V" ]] && PV="$V" && break
            done
            STATUS="—"
            case "$PN" in
                revslider|revolution-slider) STATUS="⚠️ Historically vulnerable" ;;
                wp-file-manager) STATUS="⚠️ Check for CVEs" ;;
                wpgateway) STATUS="🔴 Known backdoor vector" ;;
            esac
            echo "| $PN | $PV | $STATUS |" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
        echo "**Total:** $PC plugins" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # WP-VCD
    THEME_DIR="$SCAN_DIR/wp-content/themes"
    if [[ -d "$THEME_DIR" ]]; then
        WPVCD=$(grep -rl "wp-vcd\|class\.theme-modules\.php" "$THEME_DIR" --include="*.php" 2>/dev/null || true)
        if [[ -n "$WPVCD" ]]; then
            finding "critical" "WP-VCD Malware in Themes" \
                "WP-VCD malware detected in theme files." \
                "$WPVCD" \
                "Delete infected themes and reinstall clean copies."
        fi
    fi

    # Uploads protection
    if [[ -d "$SCAN_DIR/wp-content/uploads" && ! -f "$SCAN_DIR/wp-content/uploads/.htaccess" ]]; then
        finding "high" "No .htaccess Protection in WordPress Uploads" \
            "The uploads directory has no .htaccess to block PHP execution." \
            "" \
            "Create .htaccess in wp-content/uploads/ with rules to deny PHP execution."
    fi

    # XML-RPC
    if [[ -f "$SCAN_DIR/xmlrpc.php" ]]; then
        XMLRPC_BLOCKED=false
        [[ -f "$SCAN_DIR/.htaccess" ]] && grep -qi "xmlrpc" "$SCAN_DIR/.htaccess" 2>/dev/null && XMLRPC_BLOCKED=true
        if [[ "$XMLRPC_BLOCKED" == false ]]; then
            finding "medium" "WordPress XML-RPC Enabled" \
                "xmlrpc.php is accessible — can be used for brute force amplification." \
                "" \
                "Block XML-RPC if not needed."
        fi
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ LARAVEL                                                            │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "laravel"; then
    echo "### Laravel Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    ENV_FILE="$SCAN_DIR/.env"
    if [[ -f "$ENV_FILE" ]]; then
        if grep -qEi "^APP_DEBUG\s*=\s*true" "$ENV_FILE" 2>/dev/null; then
            finding "critical" "Laravel APP_DEBUG is Enabled" \
                "Debug mode exposes stack traces, environment variables, and database credentials." \
                "" \
                "Set APP_DEBUG=false in .env for production."
        else
            echo "✅ APP_DEBUG is disabled." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
        fi

        if grep -qEi "^APP_ENV\s*=\s*(local|development|testing)" "$ENV_FILE" 2>/dev/null; then
            finding "high" "Laravel APP_ENV Not Set to Production" \
                "Application environment is not 'production'." \
                "" \
                "Set APP_ENV=production."
        fi

        APP_KEY=$(grep "^APP_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -z "$APP_KEY" || "$APP_KEY" == "SomeRandomString" || "$APP_KEY" == "base64:" ]]; then
            finding "critical" "Laravel APP_KEY Not Set" \
                "Encryption key is missing — session data and encrypted values are insecure." \
                "" \
                "Run \`php artisan key:generate\`."
        fi

        DB_USER=$(grep "^DB_USERNAME=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ "$DB_USER" == "root" ]]; then
            finding "critical" "Laravel Using Root Database User" \
                "Connecting as root is dangerous." \
                "" \
                "Create a dedicated database user."
        fi
    fi

    if [[ -d "$SCAN_DIR/storage/logs" ]]; then
        LOG_FILES=$(find "$SCAN_DIR/storage/logs" -name "*.log" -size +0c 2>/dev/null | head -5 || true)
        if [[ -n "$LOG_FILES" ]]; then
            finding "medium" "Laravel Log Files Present" \
                "Log files may contain sensitive data. Ensure storage/ is not publicly accessible." \
                "$LOG_FILES" \
                "Block public access to the storage/ directory."
        fi
    fi

    if [[ -f "$SCAN_DIR/app/Http/Kernel.php" ]]; then
        if ! grep -q "VerifyCsrfToken" "$SCAN_DIR/app/Http/Kernel.php" 2>/dev/null; then
            finding "high" "Laravel CSRF Protection May Be Disabled" \
                "VerifyCsrfToken middleware not found in Kernel.php." \
                "" \
                "Ensure CSRF protection is active."
        fi
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ DRUPAL                                                             │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "drupal"; then
    echo "### Drupal Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    if [[ -f "$SCAN_DIR/core/lib/Drupal.php" ]]; then
        DRUPAL_VER=$(grep "const VERSION" "$SCAN_DIR/core/lib/Drupal.php" 2>/dev/null | sed "s/.*'\(.*\)'.*/\1/" || echo "unknown")
        echo "**Drupal Version:** \`$DRUPAL_VER\`" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi

    SETTINGS_FILE="$SCAN_DIR/sites/default/settings.php"
    if [[ -f "$SETTINGS_FILE" ]]; then
        SP=$(stat -c '%a' "$SETTINGS_FILE" 2>/dev/null || echo "unknown")
        if [[ "$SP" != "444" && "$SP" != "440" && "$SP" != "400" ]]; then
            finding "high" "Drupal settings.php Permissive ($SP)" \
                "settings.php contains database credentials and should be read-only." \
                "" \
                "Run \`chmod 440 sites/default/settings.php\`."
        fi
        if ! grep -q "trusted_host_patterns" "$SETTINGS_FILE" 2>/dev/null; then
            finding "medium" "Drupal Trusted Host Patterns Not Set" \
                "Vulnerable to HTTP Host header attacks." \
                "" \
                "Configure \$settings['trusted_host_patterns'] in settings.php."
        fi
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ JOOMLA                                                             │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "joomla"; then
    echo "### Joomla Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    JOOMLA_CONFIG="$SCAN_DIR/configuration.php"
    if [[ -f "$JOOMLA_CONFIG" ]]; then
        if grep -qEi "error_reporting\s*=\s*['\"]?maximum\|error_reporting\s*=\s*['\"]?development" "$JOOMLA_CONFIG" 2>/dev/null; then
            finding "high" "Joomla Error Reporting Set to Maximum" \
                "Detailed errors exposed to visitors." \
                "" \
                "Set error_reporting to 'none' in Global Configuration."
        fi

        DB_USER=$(grep -Ei "user\s*=" "$JOOMLA_CONFIG" 2>/dev/null | head -1 | sed "s/.*['\"]\\(.*\\)['\"].*/\\1/" || echo "")
        if [[ "$DB_USER" == "root" ]]; then
            finding "critical" "Joomla Using Root Database User" \
                "Connecting as root is extremely dangerous." \
                "" \
                "Create a dedicated database user."
        fi
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ NODE.JS / EXPRESS / NEXT.JS                                        │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "nodejs" || has_framework "express" || has_framework "nextjs"; then
    echo "### Node.js / Express / Next.js Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Hardcoded secrets
    HARDCODED_SECRETS=$(grep -rnEi \
        '(api_key|apikey|secret|password|token|auth)\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}' \
        "$SCAN_DIR" --include="*.js" --include="*.ts" --include="*.mjs" \
        2>/dev/null | grep -v "node_modules\|\.next/\|dist/\|build/\|\.env\|\.example" | head -20 || true)

    if [[ -n "$HARDCODED_SECRETS" ]]; then
        finding "critical" "Hardcoded Secrets in JS/TS Source Code" \
            "API keys, passwords, or tokens appear hardcoded in source files." \
            "$HARDCODED_SECRETS" \
            "Move secrets to environment variables. Rotate exposed credentials."
    fi

    if has_framework "express" && [[ -f "$SCAN_DIR/package.json" ]]; then
        if ! grep -q '"helmet"' "$SCAN_DIR/package.json" 2>/dev/null; then
            finding "medium" "Helmet.js Not Installed (Express)" \
                "The 'helmet' package sets important security HTTP headers." \
                "" \
                "Install: \`npm install helmet\` and use: \`app.use(helmet())\`."
        fi
        if ! grep -q '"express-rate-limit"\|"rate-limit"' "$SCAN_DIR/package.json" 2>/dev/null; then
            finding "medium" "No Rate Limiting (Express)" \
                "No rate-limiting package found." \
                "" \
                "Install: \`npm install express-rate-limit\`."
        fi
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ DJANGO                                                             │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "django"; then
    echo "### Django Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    DJANGO_SETTINGS=$(find "$SCAN_DIR" -name "settings.py" -not -path "*/venv/*" -not -path "*/.git/*" 2>/dev/null | head -5)

    for SF in $DJANGO_SETTINGS; do
        [[ ! -f "$SF" ]] && continue

        if grep -qEi "^\s*DEBUG\s*=\s*True" "$SF" 2>/dev/null; then
            finding "critical" "Django DEBUG Mode Enabled" \
                "DEBUG=True exposes detailed error pages with code and environment variables." \
                "File: $SF" \
                "Set DEBUG=False for production."
        fi

        if grep -qEi "SECRET_KEY.*=.*['\"]django-insecure\|SECRET_KEY.*=.*['\"]changeme" "$SF" 2>/dev/null; then
            finding "critical" "Django SECRET_KEY is Insecure" \
                "Default or weak secret key — session hijacking is trivial." \
                "" \
                "Generate a strong random key and store in environment variables."
        fi

        if grep -qEi "ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]" "$SF" 2>/dev/null; then
            finding "high" "Django ALLOWED_HOSTS Wildcard (*)" \
                "Allows HTTP Host header attacks." \
                "" \
                "Set ALLOWED_HOSTS to actual domain(s)."
        fi

        if ! grep -qEi "SECURE_SSL_REDIRECT\s*=\s*True" "$SF" 2>/dev/null; then
            finding "medium" "Django SECURE_SSL_REDIRECT Not Enabled" \
                "HTTP not redirected to HTTPS." \
                "" \
                "Set SECURE_SSL_REDIRECT=True."
        fi
    done
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ FLASK                                                              │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "flask"; then
    echo "### Flask Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    FLASK_DEBUG=$(grep -rnEi 'app\.run\s*\(.*debug\s*=\s*True\|FLASK_DEBUG\s*=\s*1' \
        "$SCAN_DIR" --include="*.py" 2>/dev/null | grep -v "venv/" | head -10 || true)

    if [[ -n "$FLASK_DEBUG" ]]; then
        finding "critical" "Flask Debug Mode Enabled" \
            "Debug mode exposes an interactive debugger allowing arbitrary code execution." \
            "$FLASK_DEBUG" \
            "Never use debug=True in production."
    fi

    FLASK_SECRET=$(grep -rnEi "secret_key\s*=\s*['\"]?(dev|secret|changeme|test)" \
        "$SCAN_DIR" --include="*.py" 2>/dev/null | grep -v "venv/" | head -5 || true)

    if [[ -n "$FLASK_SECRET" ]]; then
        finding "critical" "Flask SECRET_KEY is Insecure" \
            "Weak or default secret key." \
            "$FLASK_SECRET" \
            "Use a strong random key from environment variables."
    fi
fi

# ┌─────────────────────────────────────────────────────────────────────┐
# │ RUBY ON RAILS                                                      │
# └─────────────────────────────────────────────────────────────────────┘
if has_framework "rails"; then
    echo "### Ruby on Rails Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    if [[ -f "$SCAN_DIR/config/master.key" ]]; then
        MK_PERM=$(stat -c '%a' "$SCAN_DIR/config/master.key" 2>/dev/null || echo "unknown")
        if [[ "$MK_PERM" != "600" && "$MK_PERM" != "400" ]]; then
            finding "critical" "Rails master.key Permissive ($MK_PERM)" \
                "The master key decrypts all credentials." \
                "" \
                "Run \`chmod 600 config/master.key\`."
        fi
    fi

    RAILS_DEV=$(grep -rnEi "consider_all_requests_local\s*=\s*true" \
        "$SCAN_DIR/config" --include="*.rb" 2>/dev/null | grep "production" | head -5 || true)
    if [[ -n "$RAILS_DEV" ]]; then
        finding "high" "Rails Production Shows Full Error Details" \
            "consider_all_requests_local is true in production." \
            "$RAILS_DEV" \
            "Set to false in production.rb."
    fi
fi

# No specific framework detected
if has_framework "generic"; then
    echo "### Generic Website Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "No specific framework detected. Universal security checks have been applied above." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: DEPENDENCY & SUPPLY CHAIN RISKS
# ══════════════════════════════════════════════════════════════════════════════
log "Checking dependencies..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 6. Dependency & Supply Chain Risks

Checking for known vulnerabilities and lock file integrity.

EOF

# npm
if [[ -f "$SCAN_DIR/package.json" ]]; then
    echo "### Node.js Dependencies" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    if [[ ! -f "$SCAN_DIR/package-lock.json" && ! -f "$SCAN_DIR/yarn.lock" && ! -f "$SCAN_DIR/pnpm-lock.yaml" ]]; then
        finding "medium" "No Dependency Lock File (Node.js)" \
            "Dependency versions are not pinned." \
            "" \
            "Run \`npm install\` to generate package-lock.json and commit it."
    else
        echo "✅ Lock file found." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi

    if command -v npm &>/dev/null && [[ -f "$SCAN_DIR/package-lock.json" ]]; then
        AUDIT_OUT=$(cd "$SCAN_DIR" && npm audit 2>/dev/null | tail -20 || echo "")
        if echo "$AUDIT_OUT" | grep -qi "found.*vulnerabilit"; then
            finding "high" "npm Audit: Vulnerabilities Found" \
                "npm dependencies contain known vulnerabilities." \
                "$AUDIT_OUT" \
                "Run \`npm audit fix\`."
        else
            echo "✅ npm audit clean." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
        fi
    fi
fi

# Composer
if [[ -f "$SCAN_DIR/composer.json" ]]; then
    echo "### PHP Composer Dependencies" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    if [[ ! -f "$SCAN_DIR/composer.lock" ]]; then
        finding "medium" "No composer.lock File" \
            "PHP dependency versions are unpinned." \
            "" \
            "Run \`composer install\` and commit composer.lock."
    else
        echo "✅ composer.lock found." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi
fi

# Python
if [[ -f "$SCAN_DIR/requirements.txt" ]]; then
    echo "### Python Dependencies" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    UNPINNED=$(grep -cE '^[a-zA-Z].*[^=<>!]$' "$SCAN_DIR/requirements.txt" 2>/dev/null | head -1)
    UNPINNED=${UNPINNED:-0}
    if [[ "$UNPINNED" -gt 0 ]]; then
        finding "medium" "Unpinned Python Dependencies ($UNPINNED)" \
            "Some packages lack version pinning." \
            "" \
            "Pin all versions in requirements.txt."
    fi
fi

# Ruby
if [[ -f "$SCAN_DIR/Gemfile" && ! -f "$SCAN_DIR/Gemfile.lock" ]]; then
    echo "### Ruby Dependencies" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    finding "medium" "No Gemfile.lock" \
        "Ruby dependency versions are not locked." \
        "" \
        "Run \`bundle install\` and commit Gemfile.lock."
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: FILE PERMISSIONS AUDIT
# ══════════════════════════════════════════════════════════════════════════════
log "Auditing file permissions..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 7. File Permissions Audit

EOF

WORLD_WRITABLE=$(find "$SCAN_DIR" -type f -perm -o+w 2>/dev/null | \
    grep -v "node_modules\|/cache/\|vendor/\|\.git/" | head -30 || true)

if [[ -n "$WORLD_WRITABLE" ]]; then
    finding "high" "World-Writable Files Found" \
        "Files writable by any user on the system." \
        "$WORLD_WRITABLE" \
        "Fix: \`find $SCAN_DIR -type f -perm -o+w -exec chmod o-w {} \\;\`"
else
    echo "✅ No world-writable files." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
fi

WORLD_WRITABLE_DIRS=$(find "$SCAN_DIR" -type d -perm -o+w 2>/dev/null | \
    grep -v "node_modules\|/cache/\|vendor/\|\.git/" | head -20 || true)

if [[ -n "$WORLD_WRITABLE_DIRS" ]]; then
    finding "high" "World-Writable Directories Found" \
        "Directories writable by any user." \
        "$WORLD_WRITABLE_DIRS" \
        "Fix: \`find $SCAN_DIR -type d -perm -o+w -exec chmod o-w {} \\;\`"
else
    echo "✅ No world-writable directories." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
fi

SUID_FILES=$(find "$SCAN_DIR" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10 || true)
if [[ -n "$SUID_FILES" ]]; then
    finding "high" "SUID/SGID Files in Web Directory" \
        "Can be exploited for privilege escalation." \
        "$SUID_FILES" \
        "Remove: \`chmod u-s,g-s <file>\`."
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8: SERVER CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
log "Checking server configuration..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 8. Server Configuration Issues

EOF

# .htaccess
HTACCESS="$SCAN_DIR/.htaccess"
if [[ -f "$HTACCESS" ]]; then
    if ! grep -qi "Options.*-Indexes" "$HTACCESS" 2>/dev/null; then
        finding "medium" "Directory Listing Not Disabled" \
            "Visitors may browse directory contents." \
            "" \
            "Add \`Options -Indexes\` to .htaccess."
    fi

    SUSPICIOUS_HTACCESS=$(grep -Ein 'RewriteCond.*HTTP_USER_AGENT.*(google|bot|crawl|spider).*RewriteRule.*http' "$HTACCESS" 2>/dev/null || true)
    if [[ -n "$SUSPICIOUS_HTACCESS" ]]; then
        finding "critical" "Suspicious Bot-Targeting Redirect Rules" \
            "SEO spam redirects targeting search bots." \
            "$SUSPICIOUS_HTACCESS" \
            "Remove these rules immediately."
    fi
fi

# PHP Configuration
if command -v php &>/dev/null && $HAS_PHP; then
    echo "### PHP Configuration" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    PHP_VERSION=$(php -v 2>/dev/null | head -1 || echo "Unknown")
    echo "**PHP Version:** \`$PHP_VERSION\`" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"

    PHP_MAJOR=$(php -r 'echo PHP_MAJOR_VERSION;' 2>/dev/null || echo 0)
    PHP_MINOR=$(php -r 'echo PHP_MINOR_VERSION;' 2>/dev/null || echo 0)

    if [[ "$PHP_MAJOR" -lt 8 ]]; then
        finding "critical" "End-of-Life PHP ($PHP_MAJOR.$PHP_MINOR)" \
            "No longer receiving security updates." \
            "" \
            "Upgrade to PHP 8.1+."
    fi

    for SETTING in "allow_url_include" "display_errors"; do
        VALUE=$(php -r "echo ini_get('$SETTING');" 2>/dev/null || echo "")
        if [[ "$VALUE" == "1" || "$VALUE" == "On" ]]; then
            SEV="high"
            [[ "$SETTING" == "allow_url_include" ]] && SEV="critical"
            finding "$SEV" "PHP: $SETTING is enabled" \
                "This setting poses a security risk in production." \
                "" \
                "Set \`$SETTING = Off\` in php.ini."
        fi
    done

    DISABLED_FUNCS=$(php -r "echo ini_get('disable_functions');" 2>/dev/null || echo "")
    MISSING=""
    for FUNC in "exec" "passthru" "shell_exec" "system" "proc_open" "popen"; do
        [[ "$DISABLED_FUNCS" != *"$FUNC"* ]] && MISSING+="$FUNC, "
    done
    if [[ -n "$MISSING" ]]; then
        finding "medium" "Dangerous PHP Functions Not Disabled" \
            "Available: ${MISSING%, }" \
            "" \
            "Add to disable_functions in php.ini."
    fi
fi

# Node.js version
if command -v node &>/dev/null && $HAS_JS; then
    NODE_VER=$(node -v 2>/dev/null || echo "unknown")
    echo "### Node.js Runtime" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    echo "**Version:** \`$NODE_VER\`" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v//' | cut -d. -f1 | tr -dc '0-9')
    NODE_MAJOR=${NODE_MAJOR:-0}
    if [[ "$NODE_MAJOR" -lt 18 ]]; then
        finding "high" "Outdated Node.js ($NODE_VER)" \
            "May be end-of-life." \
            "" \
            "Upgrade to Node.js 18 LTS or newer."
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9: SECRETS & CREDENTIAL EXPOSURE
# ══════════════════════════════════════════════════════════════════════════════
log "Scanning for exposed secrets..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 9. Secrets & Credential Exposure

EOF

# Sensitive files
SENSITIVE_PATTERNS=(
    ".env" ".env.local" ".env.production" ".env.backup"
    ".git/config" ".svn/entries"
    "phpinfo.php" "info.php" "test.php"
    "debug.log" "error.log" "error_log"
    "wp-config.php.bak" "wp-config.php.old" "wp-config.txt"
    ".htpasswd" "id_rsa" "id_ed25519" "privkey.pem" "server.key"
    "dump.sql" "backup.sql" "database.sql"
    "credentials.json" "service-account.json"
    ".npmrc" ".pypirc"
)

FOUND_SENSITIVE=""
for P in "${SENSITIVE_PATTERNS[@]}"; do
    MATCHES=$(find "$SCAN_DIR" -maxdepth 3 -name "$P" -type f 2>/dev/null | \
        grep -v "node_modules\|vendor/\|venv/" || true)
    while IFS= read -r F; do
        [[ -z "$F" ]] && continue
        FSIZE=$(stat -c%s "$F" 2>/dev/null || echo "?")
        FOUND_SENSITIVE+="$F ($FSIZE bytes)"$'\n'
    done <<< "$MATCHES"
done

SQL_DUMPS=$(find "$SCAN_DIR" -maxdepth 3 \( -name "*.sql" -o -name "*.sql.gz" \) -type f \
    2>/dev/null | grep -v "node_modules\|vendor/" | head -10 || true)
[[ -n "$SQL_DUMPS" ]] && FOUND_SENSITIVE+="$SQL_DUMPS"$'\n'

if [[ -n "$FOUND_SENSITIVE" ]]; then
    finding "critical" "Sensitive Files Exposed" \
        "Config backups, credentials, database dumps, or private keys found in web-accessible locations." \
        "$FOUND_SENSITIVE" \
        "Remove or move outside web root. Rotate any exposed credentials."
else
    echo "✅ No exposed sensitive files." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
fi

# Hardcoded credentials
CRED_PATTERNS=(
    '(password|passwd|pwd)\s*[:=]\s*["\x27][^\s"'\'']{8,}'
    '(api[_-]?key|apikey)\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}'
    '(secret[_-]?key|app[_-]?secret)\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}'
    'AKIA[0-9A-Z]{16}'
    'sk[_-]live[_-][A-Za-z0-9]{20,}'
    'ghp_[A-Za-z0-9]{36}'
    'glpat-[A-Za-z0-9_-]{20,}'
    'xox[bpras]-[A-Za-z0-9-]+'
)
CRED_REGEX=$(IFS='|'; echo "${CRED_PATTERNS[*]}")
CRED_RESULTS=$(grep -rnEi "$CRED_REGEX" "$SCAN_DIR" \
    --include="*.php" --include="*.py" --include="*.js" --include="*.ts" \
    --include="*.rb" --include="*.yml" --include="*.yaml" --include="*.json" \
    --include="*.conf" --include="*.cfg" --include="*.ini" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/\|dist/\|\.example\|\.sample\|\.md\|test" | head -30 || true)

if [[ -n "$CRED_RESULTS" ]]; then
    finding "critical" "Hardcoded Credentials or API Keys" \
        "Passwords, API keys, or tokens found in source code." \
        "$CRED_RESULTS" \
        "Move to environment variables or secrets manager. Rotate exposed keys."
else
    echo "✅ No hardcoded credentials detected." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
fi

# .git exposure
if [[ -d "$SCAN_DIR/.git" ]]; then
    finding "critical" ".git Directory Exposed" \
        "Attackers can download entire source code and history." \
        "" \
        "Block .git access via server config or remove from web root."
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10: NETWORK & ACCESS SECURITY
# ══════════════════════════════════════════════════════════════════════════════
log "Checking network & access security..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 10. Network & Access Security

EOF

# Security headers
for CONF_FILE in "/etc/nginx/nginx.conf" "/etc/nginx/sites-enabled/default" \
    "/etc/apache2/apache2.conf" "$SCAN_DIR/.htaccess"; do
    if [[ -f "$CONF_FILE" ]]; then
        MISSING_HEADERS=""
        grep -qi "X-Content-Type-Options" "$CONF_FILE" 2>/dev/null || MISSING_HEADERS+="X-Content-Type-Options, "
        grep -qi "X-Frame-Options" "$CONF_FILE" 2>/dev/null || MISSING_HEADERS+="X-Frame-Options, "
        grep -qi "Strict-Transport-Security" "$CONF_FILE" 2>/dev/null || MISSING_HEADERS+="HSTS, "
        grep -qi "Content-Security-Policy" "$CONF_FILE" 2>/dev/null || MISSING_HEADERS+="CSP, "

        if [[ -n "$MISSING_HEADERS" ]]; then
            finding "medium" "Missing Security Headers" \
                "Not configured in $CONF_FILE: ${MISSING_HEADERS%, }" \
                "" \
                "Add security headers to prevent clickjacking, XSS, MIME sniffing, and downgrade attacks."
            break
        fi
    fi
done

# CORS wildcard
CORS_WILDCARD=$(grep -rnEi 'Access-Control-Allow-Origin.*\*|cors.*origin.*\*' \
    "$SCAN_DIR" --include="*.php" --include="*.js" --include="*.py" --include="*.conf" \
    2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" | head -10 || true)

if [[ -n "$CORS_WILDCARD" ]]; then
    finding "medium" "CORS Wildcard (*) Detected" \
        "Any website can make requests to your API." \
        "$CORS_WILDCARD" \
        "Restrict to specific trusted domains."
fi

# Suspicious crontab
if command -v crontab &>/dev/null; then
    CRON_ENTRIES=$(crontab -l 2>/dev/null || true)
    CRON_SUS=$(echo "$CRON_ENTRIES" | grep -Ei 'wget|curl.*\|.*sh|base64|eval|python.*-c' 2>/dev/null || true)
    if [[ -n "$CRON_SUS" ]]; then
        finding "high" "Suspicious Crontab Entries" \
            "Entries that download and execute remote code." \
            "$CRON_SUS" \
            "Review and remove unauthorized cron jobs."
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11: RECENTLY MODIFIED FILES
# ══════════════════════════════════════════════════════════════════════════════
log "Checking recently modified files..."

cat >> "$REPORT_FILE" <<'EOF'
---

## 11. Recently Modified Files

EOF

RECENT_MODIFIED=$(find "$SCAN_DIR" -type f \( \
    -name "*.php" -o -name "*.js" -o -name "*.py" -o -name "*.rb" \
    -o -name "*.html" -o -name "*.sh" \
    \) -mtime -3 2>/dev/null | \
    grep -v "node_modules\|vendor/\|\.git/\|cache\|venv/\|__pycache__\|dist/\|build/\|\.next/" | \
    sort | head -50 || true)

if [[ -n "$RECENT_MODIFIED" ]]; then
    echo "Files modified in the last 3 days:" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo '```' >> "$REPORT_FILE"
    echo "$RECENT_MODIFIED" >> "$REPORT_FILE"
    echo '```' >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "> Review if no recent deployments were performed." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
else
    echo "✅ No source files modified in the last 3 days." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
fi


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY (inserted at top)
# ══════════════════════════════════════════════════════════════════════════════
log "Generating executive summary..."

# Calculate security score and grade
SCORE_DATA=$(calculate_security_score)
SECURITY_SCORE=$(echo "$SCORE_DATA" | cut -d: -f1)
SECURITY_GRADE=$(echo "$SCORE_DATA" | cut -d: -f2)
GRADE_EMOJI=$(echo "$SCORE_DATA" | cut -d: -f3)
GRADE_DESC=$(get_grade_description "$SECURITY_GRADE")

if [[ "$CRITICAL" -gt 0 ]]; then
    RISK_LEVEL="🔴 CRITICAL"
    RISK_DESC="Critical security issues require immediate action. The website may already be compromised."
elif [[ "$HIGH" -gt 0 ]]; then
    RISK_LEVEL="🟠 HIGH"
    RISK_DESC="Significant security weaknesses should be addressed urgently."
elif [[ "$MEDIUM" -gt 0 ]]; then
    RISK_LEVEL="🟡 MEDIUM"
    RISK_DESC="Moderate security issues should be addressed in the near term."
elif [[ "$LOW" -gt 0 ]]; then
    RISK_LEVEL="🔵 LOW"
    RISK_DESC="Minor improvements recommended but no serious threats detected."
else
    RISK_LEVEL="🟢 CLEAN"
    RISK_DESC="No significant issues detected. Continue monitoring and keep everything updated."
fi

SUMMARY=$(cat <<EOF

## Executive Summary

### Security Grade: $GRADE_EMOJI **$SECURITY_GRADE** (Score: $SECURITY_SCORE/100)

$GRADE_DESC

### Overall Risk Level: $RISK_LEVEL

$RISK_DESC

| Severity | Count |
|----------|-------|
| 🔴 Critical | $CRITICAL |
| 🟠 High | $HIGH |
| 🟡 Medium | $MEDIUM |
| 🔵 Low | $LOW |
| ℹ️ Info | $INFO |
| **Total Issues** | **$TOTAL_ISSUES** |

**Frameworks Detected:** $FW_LIST

---

### Scoring Methodology

| Grade | Score Range | Description |
|-------|-------------|-------------|
| **A** | 90-100 | Excellent - Strong security posture |
| **B** | 80-89 | Good - Minor improvements needed |
| **C** | 70-79 | Fair - Notable vulnerabilities present |
| **D** | 60-69 | Poor - Significant risks require attention |
| **E** | 50-59 | Critical - Severe vulnerabilities |
| **F** | 0-49 | Failed - Critical compromise likely |

*Scoring: Critical (-25), High (-15), Medium (-5), Low (-2), Info (0)*

EOF
)

TEMP_REPORT=$(mktemp)
awk -v summary="$SUMMARY" 'BEGIN { found=0 } /^---$/ && found==0 { print; print ""; print summary; found=1; next } {print}' \
    "$REPORT_FILE" > "$TEMP_REPORT"
mv "$TEMP_REPORT" "$REPORT_FILE"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12: RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════
cat >> "$REPORT_FILE" <<'EOF'
---

## Recommendations

### Immediate Actions (if critical issues found)

1. **Quarantine infected files** — Move malicious files outside the web root
2. **Reset all credentials** — Admin passwords, database passwords, API keys, SSH keys
3. **Replace framework core files** — Download fresh copies matching your version
4. **Audit the database** — Check for injected content and unauthorized users
5. **Check crontab** — Run `crontab -l` and inspect for unauthorized entries
6. **Scan other sites** — If on shared hosting, check other sites on the same account

### Universal Hardening Checklist

- [ ] Update all frameworks, libraries, and dependencies to latest versions
- [ ] Remove unused plugins, themes, packages, and dead code
- [ ] Set proper file permissions (dirs: 755, files: 644, configs: 640)
- [ ] Block script execution in upload/media directories
- [ ] Use strong passwords and enable 2FA for all admin accounts
- [ ] Move sensitive files outside web root (.env, backups, SQL dumps)
- [ ] Install a Web Application Firewall (WAF)
- [ ] Set up automated backups (files + database)
- [ ] Enforce HTTPS site-wide
- [ ] Configure security headers (CSP, HSTS, X-Frame-Options)
- [ ] Implement rate limiting on login and API endpoints
- [ ] Disable directory listing
- [ ] Block .git, .env, and sensitive files via server config
- [ ] Use environment variables for all secrets
- [ ] Schedule regular security scans (weekly minimum)

### Security Headers

```apache
# Apache (.htaccess)
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

```nginx
# Nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### Framework Security Guides

| Framework | Guide |
|-----------|-------|
| WordPress | [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/) |
| Laravel | [Laravel Security Docs](https://laravel.com/docs/security) |
| Django | [Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/) |
| Express.js | [Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html) |
| Drupal | [Security in Drupal](https://www.drupal.org/docs/security-in-drupal) |
| Rails | [Security Guide](https://guides.rubyonrails.org/security.html) |
| Flask | [Security Considerations](https://flask.palletsprojects.com/en/latest/security/) |

---

EOF

cat >> "$REPORT_FILE" <<EOF
*Report generated by Universal Web Security Scanner v3.0 on $(date '+%B %d, %Y at %H:%M:%S %Z')*
*Automated scan — manual review of flagged items is recommended.*
*For critical findings, consider engaging a professional security auditor.*
EOF


# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK DELIVERY
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$WEBHOOK_URL" ]]; then
    log "Sending report to webhook..."

    # Clean risk level and grade (remove emoji)
    CLEAN_RISK=$(echo "$RISK_LEVEL" | sed 's/^[^ ]* //')
    CLEAN_GRADE=$(echo "$SECURITY_GRADE" | sed 's/[^A-F]*//g')

    # Read report content and escape for JSON
    REPORT_CONTENT=$(cat "$REPORT_FILE")

    # Build JSON payload using python for safe escaping (available on most servers)
    # Falls back to basic sed escaping if python is not available
    if command -v python3 &>/dev/null; then
        JSON_PAYLOAD=$(python3 -c "
import json, sys
data = {
    'api_key': sys.argv[1],
    'email': sys.argv[2],
    'hostname': sys.argv[3],
    'scan_target': sys.argv[4],
    'frameworks': sys.argv[5],
    'risk_level': sys.argv[6],
    'security_grade': sys.argv[7],
    'security_score': int(sys.argv[8]),
    'total_issues': int(sys.argv[9]),
    'critical': int(sys.argv[10]),
    'high': int(sys.argv[11]),
    'medium': int(sys.argv[12]),
    'low': int(sys.argv[13]),
    'info': int(sys.argv[14]),
    'report': sys.stdin.read()
}
print(json.dumps(data))
" "$API_KEY" "$NOTIFY_EMAIL" "$(hostname 2>/dev/null || echo unknown)" "$SCAN_DIR" \
  "$FW_LIST" "$CLEAN_RISK" "$SECURITY_GRADE" "$SECURITY_SCORE" \
  "$TOTAL_ISSUES" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$INFO" \
  < "$REPORT_FILE")
    elif command -v python &>/dev/null; then
        JSON_PAYLOAD=$(python -c "
import json, sys
data = {
    'api_key': sys.argv[1],
    'email': sys.argv[2],
    'hostname': sys.argv[3],
    'scan_target': sys.argv[4],
    'frameworks': sys.argv[5],
    'risk_level': sys.argv[6],
    'security_grade': sys.argv[7],
    'security_score': int(sys.argv[8]),
    'total_issues': int(sys.argv[9]),
    'critical': int(sys.argv[10]),
    'high': int(sys.argv[11]),
    'medium': int(sys.argv[12]),
    'low': int(sys.argv[13]),
    'info': int(sys.argv[14]),
    'report': sys.stdin.read()
}
print(json.dumps(data))
" "$API_KEY" "$NOTIFY_EMAIL" "$(hostname 2>/dev/null || echo unknown)" "$SCAN_DIR" \
  "$FW_LIST" "$CLEAN_RISK" "$SECURITY_GRADE" "$SECURITY_SCORE" \
  "$TOTAL_ISSUES" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$INFO" \
  < "$REPORT_FILE")
    else
        # Fallback: basic JSON escaping with sed
        ESCAPED_REPORT=$(cat "$REPORT_FILE" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | \
            awk '{printf "%s\\n", $0}')
        JSON_PAYLOAD=$(cat <<JSONEOF
{
  "api_key": "$API_KEY",
  "email": "$NOTIFY_EMAIL",
  "hostname": "$(hostname 2>/dev/null || echo unknown)",
  "scan_target": "$SCAN_DIR",
  "frameworks": "$FW_LIST",
  "risk_level": "$CLEAN_RISK",
  "security_grade": "$SECURITY_GRADE",
  "security_score": $SECURITY_SCORE,
  "total_issues": $TOTAL_ISSUES,
  "critical": $CRITICAL,
  "high": $HIGH,
  "medium": $MEDIUM,
  "low": $LOW,
  "info": $INFO,
  "report": "$ESCAPED_REPORT"
}
JSONEOF
)
    fi

    # Send via curl
    HTTP_RESPONSE=$(curl -s -o "$TEMP_DIR/webhook_response.txt" -w "%{http_code}" \
        -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD" \
        --max-time 30 \
        2>/dev/null || echo "000")

    if [[ "$HTTP_RESPONSE" == "200" ]]; then
        ok "Report sent successfully to webhook"
        RESPONSE_MSG=$(cat "$TEMP_DIR/webhook_response.txt" 2>/dev/null || echo "")
        [[ -n "$RESPONSE_MSG" ]] && log "Server response: $RESPONSE_MSG"
    else
        err "Webhook delivery failed (HTTP $HTTP_RESPONSE)"
        [[ -f "$TEMP_DIR/webhook_response.txt" ]] && err "Response: $(cat "$TEMP_DIR/webhook_response.txt")"
        warn "Report is still saved locally: $REPORT_FILE"
    fi
fi


# ══════════════════════════════════════════════════════════════════════════════
# FINAL OUTPUT
# ══════════════════════════════════════════════════════════════════════════════
# Calculate scan duration
SCAN_END_TIME=$(date +%s)
SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))
DURATION_MIN=$((SCAN_DURATION / 60))
DURATION_SEC=$((SCAN_DURATION % 60))

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                       SCAN COMPLETE                            ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
log "Security Grade : $GRADE_EMOJI $SECURITY_GRADE (Score: $SECURITY_SCORE/100)"
log "Frameworks     : $FW_LIST"
log "Risk Level     : $RISK_LEVEL"
log "Total Issues   : $TOTAL_ISSUES"
[[ "$CRITICAL" -gt 0 ]] && err "  Critical : $CRITICAL"
[[ "$HIGH" -gt 0 ]]     && warn "  High     : $HIGH"
[[ "$MEDIUM" -gt 0 ]]   && warn "  Medium   : $MEDIUM"
[[ "$LOW" -gt 0 ]]      && ok "  Low      : $LOW"
[[ "$INFO" -gt 0 ]]     && ok "  Info     : $INFO"
echo ""
log "Scan Duration  : ${DURATION_MIN}m ${DURATION_SEC}s"
log "Files Scanned  : $(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)"
log "Report saved to: $(pwd)/$REPORT_FILE"
echo ""
