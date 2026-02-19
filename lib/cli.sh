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
    echo "  --no-recommendations      Hide recommendations section from report"
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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --webhook)       WEBHOOK_URL="$2"; shift 2 ;;
            --api-key)       API_KEY="$2"; shift 2 ;;
            --email)         NOTIFY_EMAIL="$2"; EMAIL_ENABLED=true; shift 2 ;;
            --no-email)      NO_EMAIL=true; shift ;;
            --no-recommendations) SHOW_RECOMMENDATIONS=false; shift ;;
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
        [[ "$SHOW_RECOMMENDATIONS" == false ]] && EXTRA_ARGS+=" --no-recommendations"
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
        [[ "$SHOW_RECOMMENDATIONS" == false ]] && BG_ARGS+=(--no-recommendations)

        echo ""
        echo -e "${GREEN}[OK]${NC} Scan launched in background!"
        echo -e "  Log file : ${BOLD}${BG_LOG}${NC}"
        echo -e "  Monitor  : ${CYAN}tail -f ${BG_LOG}${NC}"
        echo ""
        nohup "$WEBSCAN_BIN" "${BG_ARGS[@]}" > "$BG_LOG" 2>&1 &
        disown
        exit 0
    fi
}

validate_input() {
    if [[ ! -d "$SCAN_DIR" ]]; then
        err "Directory '$SCAN_DIR' does not exist."
        echo "Usage: sudo bash $0 /path/to/website"
        exit 1
    fi

    SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
    REPORT_FILE="${SCAN_DIR}/security-report_${TIMESTAMP}.md"

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
}
