# ── Argument Parsing ────────────────────────────────────────────────────────
NO_EMAIL=false
CRON_SCHEDULE=""
OUTPUT_FORMATS=()   # "html" "json" "sarif" "all" — in addition to always-on markdown

show_usage() {
    echo "Usage: webscan <path> [options]"
    echo ""
    echo "Arguments:"
    echo "  <path>                    Path to the website root directory"
    echo ""
    echo "Scan Options:"
    echo "  --url <url>               Base URL of the site for HTTP accessibility checks (e.g. https://example.com)"
    echo "  --webhook <url>           Send report to a webhook endpoint via POST"
    echo "  --api-key <key>           API key for webhook authentication"
    echo "  --email <address>         Recipient email for this scan"
    echo "  --no-email                Skip email notification for this scan"
    echo "  --no-recommendations      Hide recommendations section from report"
    echo "  --no-allowlist            Disable built-in allowlisting (scan everything)"
    echo "  --background              Run scan in background (survives terminal close)"
    echo "  --cron <schedule>         Set up a cron job for recurring scans"
    echo "                            Shortcuts: hourly, daily, weekly, monthly"
    echo "                            Custom:    '0 2 * * *' (cron expression)"
    echo "  --remove-cron             Remove all webscan cron jobs"
    echo "  --list-cron               List active webscan cron jobs"
    echo ""
    echo "Output Formats:"
    echo "  --output <format>         Generate additional output format (repeatable):"
    echo "                              html   = self-contained HTML report with charts"
    echo "                              json   = machine-readable JSON (CI/CD integration)"
    echo "                              sarif  = SARIF 2.1.0 (GitHub Security tab)"
    echo "                              all    = all formats above"
    echo "  Markdown report is always generated."
    echo ""
    echo "Auto-Remediation:"
    echo "  --fix                     Interactively fix common issues after scan"
    echo "  --fix-auto                Auto-apply all safe fixes without prompting"
    echo "  --restore <id>            Restore a quarantined file by ID"
    echo "  --list-quarantine         List all quarantined files"
    echo ""
    echo "Baseline / Diff Scanning:"
    echo "  --baseline save           Save a cryptographic baseline of the site"
    echo "  --baseline compare        Compare current scan against saved baseline"
    echo "  --baseline list           List all saved baselines"
    echo "  --baseline delete <name>  Delete a named baseline"
    echo "  --baseline-name <name>    Name for the baseline (default: auto-timestamp)"
    echo ""
    echo "Scan Scope (Speed & Compatibility):"
    echo "  --mode <mode>             Scan scope — one of:"
    echo "                              all    = full scan, all 15 sections (default)"
    echo "                              files  = file-based checks only (shared-hosting safe)"
    echo "                              server = server-level checks only (needs root access)"
    echo "  --skip <module>           Skip one module for this run (repeatable)"
    echo "  --only <module>           Run only this one module"
    echo ""
    echo "  Module names for --skip / --only:"
    echo "    FILE-BASED:   malware  suspicious  obfuscation  integrity  framework"
    echo "                  dependencies  permissions  secrets  modified-files"
    echo "    SERVER-LEVEL: server-config  network  ssl  database  container  logging"
    echo ""
    echo "Configuration:"
    echo "  --set-email <address>     Save default email address"
    echo "  --enable-email            Enable email notifications by default"
    echo "  --disable-email           Disable email notifications by default"
    echo "  --set-webhook <url>       Save default webhook URL"
    echo "  --set-api-key <key>       Save default API key"
    echo "  --set-smtp-host <host>    SMTP server (e.g. smtp.gmail.com:587)"
    echo "  --set-smtp-user <email>   SMTP username / sender address"
    echo "  --set-smtp-pass <pass>    SMTP password or app-specific password"
    echo "  --set-smtp-from <from>    From header (e.g. 'Scanner <you@example.com>')"
    echo "  --test-email <address>    Send a test email to verify SMTP settings"
    echo "  --show-config             Show current configuration"
    echo "  --edit-config             Open config file in editor"
    echo "  --help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  webscan /var/www/html"
    echo "  webscan /var/www/html --output html                  # HTML report"
    echo "  webscan /var/www/html --output json --output sarif   # For CI/CD"
    echo "  webscan /var/www/html --output all                   # All formats"
    echo "  webscan /var/www/html --fix                          # Interactive fix"
    echo "  webscan /var/www/html --fix-auto                     # Auto-fix"
    echo "  webscan /var/www/html --baseline save                # Save baseline"
    echo "  webscan /var/www/html --baseline compare             # Diff report"
    echo "  webscan /var/www/html --mode files           # Shared-hosting safe scan"
    echo "  webscan /var/www/html --mode server          # Server config audit only"
    echo "  webscan /var/www/html --skip database        # Skip DB checks"
    echo "  webscan /var/www/html --only malware         # Malware check only"
    echo "  webscan /var/www/html --email admin@site.com"
    echo "  webscan --set-smtp-host smtp.gmail.com:587"
    echo "  webscan --test-email admin@site.com"
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
            --url)           SITE_URL="$2"; shift 2 ;;
            --webhook)       WEBHOOK_URL="$2"; shift 2 ;;
            --api-key)       API_KEY="$2"; shift 2 ;;
            --email)         NOTIFY_EMAIL="$2"; EMAIL_ENABLED=true; shift 2 ;;
            --no-email)      NO_EMAIL=true; shift ;;
            --no-recommendations) SHOW_RECOMMENDATIONS=false; shift ;;
            --no-allowlist)      USE_ALLOWLIST=false; shift ;;
            # ── Output formats ─────────────────────────────────────────────
            --output)
                case "$2" in
                    html|json|sarif) OUTPUT_FORMATS+=("$2") ;;
                    all)             OUTPUT_FORMATS+=("html" "json" "sarif") ;;
                    markdown)        ;;  # always on, no-op
                    *) echo "Unknown output format '$2'. Valid: html json sarif all markdown"; exit 1 ;;
                esac
                shift 2 ;;
            # ── Auto-remediation ───────────────────────────────────────────
            --fix)           FIX_MODE=true; shift ;;
            --fix-auto)      FIX_MODE=true; FIX_AUTO=true; shift ;;
            --restore)       restore_quarantine "$2" ;;
            --list-quarantine) list_quarantine ;;
            # ── Baseline scanning ──────────────────────────────────────────
            --baseline)
                case "$2" in
                    save|compare|list|delete) BASELINE_MODE="$2" ;;
                    *) echo "Unknown baseline mode '$2'. Valid: save compare list delete"; exit 1 ;;
                esac
                shift 2 ;;
            --baseline-name) BASELINE_NAME="$2"; shift 2 ;;
            # ── SMTP configuration ─────────────────────────────────────────
            --set-smtp-host) config_set "SMTP_HOST" "$2"; exit 0 ;;
            --set-smtp-user) config_set "SMTP_USER" "$2"; exit 0 ;;
            --set-smtp-pass) config_set "SMTP_PASS" "$2"; exit 0 ;;
            --set-smtp-from) config_set "SMTP_FROM" "$2"; exit 0 ;;
            --test-email)    send_test_email "$2" ;;  # exits inside function
            --mode)
                SCAN_MODE="$2"
                case "$SCAN_MODE" in
                    files)
                        # Disable all server-level modules — safe on shared hosting
                        SCAN_08_SERVER_CONFIG=false
                        SCAN_10_NETWORK=false
                        SCAN_12_SSL=false
                        SCAN_13_DATABASE=false
                        SCAN_14_CONTAINER=false
                        SCAN_15_LOGGING=false
                        ;;
                    server)
                        # Disable all file-based modules — only run server checks
                        SCAN_01_MALWARE=false
                        SCAN_02_SUSPICIOUS=false
                        SCAN_03_OBFUSCATION=false
                        SCAN_04_INTEGRITY=false
                        SCAN_05_FRAMEWORK=false
                        SCAN_06_DEPENDENCIES=false
                        SCAN_07_PERMISSIONS=false
                        SCAN_09_SECRETS=false
                        SCAN_11_MODIFIED_FILES=false
                        ;;
                    all) ;;  # Default — nothing to change
                    *) echo "Unknown --mode '$2'. Valid values: all, files, server"; exit 1 ;;
                esac
                shift 2 ;;
            --skip)
                case "$2" in
                    malware)        SCAN_01_MALWARE=false ;;
                    suspicious)     SCAN_02_SUSPICIOUS=false ;;
                    obfuscation)    SCAN_03_OBFUSCATION=false ;;
                    integrity)      SCAN_04_INTEGRITY=false ;;
                    framework)      SCAN_05_FRAMEWORK=false ;;
                    dependencies)   SCAN_06_DEPENDENCIES=false ;;
                    permissions)    SCAN_07_PERMISSIONS=false ;;
                    server-config)  SCAN_08_SERVER_CONFIG=false ;;
                    secrets)        SCAN_09_SECRETS=false ;;
                    network)        SCAN_10_NETWORK=false ;;
                    modified-files) SCAN_11_MODIFIED_FILES=false ;;
                    ssl)            SCAN_12_SSL=false ;;
                    database)       SCAN_13_DATABASE=false ;;
                    container)      SCAN_14_CONTAINER=false ;;
                    logging)        SCAN_15_LOGGING=false ;;
                    *) echo "Unknown module '$2'. Run --help to see valid module names."; exit 1 ;;
                esac
                shift 2 ;;
            --only)
                # Disable everything first, then re-enable the one requested
                SCAN_01_MALWARE=false; SCAN_02_SUSPICIOUS=false; SCAN_03_OBFUSCATION=false
                SCAN_04_INTEGRITY=false; SCAN_05_FRAMEWORK=false; SCAN_06_DEPENDENCIES=false
                SCAN_07_PERMISSIONS=false; SCAN_08_SERVER_CONFIG=false; SCAN_09_SECRETS=false
                SCAN_10_NETWORK=false; SCAN_11_MODIFIED_FILES=false; SCAN_12_SSL=false
                SCAN_13_DATABASE=false; SCAN_14_CONTAINER=false; SCAN_15_LOGGING=false
                case "$2" in
                    malware)        SCAN_01_MALWARE=true ;;
                    suspicious)     SCAN_02_SUSPICIOUS=true ;;
                    obfuscation)    SCAN_03_OBFUSCATION=true ;;
                    integrity)      SCAN_04_INTEGRITY=true ;;
                    framework)      SCAN_05_FRAMEWORK=true ;;
                    dependencies)   SCAN_06_DEPENDENCIES=true ;;
                    permissions)    SCAN_07_PERMISSIONS=true ;;
                    server-config)  SCAN_08_SERVER_CONFIG=true ;;
                    secrets)        SCAN_09_SECRETS=true ;;
                    network)        SCAN_10_NETWORK=true ;;
                    modified-files) SCAN_11_MODIFIED_FILES=true ;;
                    ssl)            SCAN_12_SSL=true ;;
                    database)       SCAN_13_DATABASE=true ;;
                    container)      SCAN_14_CONTAINER=true ;;
                    logging)        SCAN_15_LOGGING=true ;;
                    *) echo "Unknown module '$2'. Run --help to see valid module names."; exit 1 ;;
                esac
                shift 2 ;;
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
        [[ "$USE_ALLOWLIST" == false ]] && EXTRA_ARGS+=" --no-allowlist"
        [[ "$SCAN_MODE" != "all" ]] && EXTRA_ARGS+=" --mode $SCAN_MODE"
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
        [[ "$USE_ALLOWLIST" == false ]] && BG_ARGS+=(--no-allowlist)
        [[ "$SCAN_MODE" != "all" ]] && BG_ARGS+=(--mode "$SCAN_MODE")

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
