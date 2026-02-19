# ── Cron Helper Functions ────────────────────────────────────────────────────
CRON_MARKER="# webscan-auto"
WEBSCAN_BIN=$(command -v webscan 2>/dev/null || echo "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/$(basename "$0")")

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
