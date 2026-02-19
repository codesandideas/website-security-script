scan_section_15() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 15: LOGGING & MONITORING
    # ══════════════════════════════════════════════════════════════════════════════
    log "Checking logging and monitoring..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 15. Logging & Monitoring

Checking access log configuration, error logging, and sensitive data exposure in logs.

EOF

    # Collect server config files (also used by section 12, duplicated here for parallel safety)
    SSL_CONFIG_FILES=""
    for cfg in /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*; do
        [[ -f "$cfg" ]] 2>/dev/null && SSL_CONFIG_FILES="$SSL_CONFIG_FILES $cfg"
    done

    # ── 15a. Missing Access Logs ──────────────────────────────────────────────────
    ACCESS_LOG_CONFIGURED=false
    ACCESS_LOG_MISSING=""

    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        ACCESS_LOG_CFG=$(grep -hEi 'access_log|CustomLog' $SSL_CONFIG_FILES 2>/dev/null | grep -v '^\s*#' || true)
        if [[ -n "$ACCESS_LOG_CFG" ]]; then
            ACCESS_LOG_CONFIGURED=true
            # Check if referenced log files actually exist
            LOG_PATHS=$(echo "$ACCESS_LOG_CFG" | grep -oE '/[^ ;]+\.log' || true)
            while IFS= read -r lp; do
                if [[ -n "$lp" && ! -f "$lp" ]]; then
                    ACCESS_LOG_MISSING="$ACCESS_LOG_MISSING\nConfigured but missing: $lp"
                fi
            done <<< "$LOG_PATHS"
        fi
    fi

    if [[ "$ACCESS_LOG_CONFIGURED" != true ]]; then
        finding "medium" "No Access Log Configuration Found" \
            "No access log directives found in server configuration files." \
            "Searched for access_log (Nginx) and CustomLog (Apache) directives." \
            "Configure access logging to track all HTTP requests for security monitoring and incident response."
    elif [[ -n "$ACCESS_LOG_MISSING" ]]; then
        finding "medium" "Access Log Files Missing" \
            "Access logging is configured but the log files do not exist." \
            "$(echo -e "$ACCESS_LOG_MISSING")" \
            "Ensure the log directory exists and the web server has write permissions."
    else
        echo "✅ Access logging is configured and log files exist." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 15b. Missing Error Logging ────────────────────────────────────────────────
    ERROR_LOG_CONFIGURED=false

    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        ERROR_LOG_CFG=$(grep -hEi 'error_log|ErrorLog' $SSL_CONFIG_FILES 2>/dev/null | grep -v '^\s*#' || true)
        if [[ -n "$ERROR_LOG_CFG" ]]; then
            ERROR_LOG_CONFIGURED=true
        fi
    fi

    if [[ "$ERROR_LOG_CONFIGURED" != true ]]; then
        finding "medium" "No Error Log Configuration Found" \
            "No error log directives found in server configuration files." \
            "Searched for error_log (Nginx) and ErrorLog (Apache) directives." \
            "Configure error logging to capture application errors and security events."
    else
        echo "✅ Error logging is configured." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 15c. Sensitive Data in Logs ───────────────────────────────────────────────
    SENSITIVE_IN_LOGS=""
    LOG_FILES_TO_CHECK=""

    # Find recent log files
    for log_dir in /var/log/nginx /var/log/apache2 /var/log/httpd; do
        if [[ -d "$log_dir" ]]; then
            LOG_FILES_TO_CHECK="$LOG_FILES_TO_CHECK $(find "$log_dir" -name "*.log" -type f -mtime -7 2>/dev/null | head -5 || true)"
        fi
    done

    if [[ -n "$LOG_FILES_TO_CHECK" ]]; then
        for log_file in $LOG_FILES_TO_CHECK; do
            # Check last 1000 lines for sensitive patterns
            SENSITIVE=$(tail -1000 "$log_file" 2>/dev/null | grep -Ein 'password=|passwd=|token=|api_key=|secret=|credit.card|ssn=|\b[0-9]{13,16}\b' 2>/dev/null | head -5 || true)
            if [[ -n "$SENSITIVE" ]]; then
                SENSITIVE_IN_LOGS="$SENSITIVE_IN_LOGS\n$log_file:\n$SENSITIVE"
            fi
        done
    fi

    if [[ -n "$SENSITIVE_IN_LOGS" ]]; then
        finding "high" "Sensitive Data Found in Log Files" \
            "Log files contain potentially sensitive data such as passwords, tokens, or credit card numbers." \
            "$(echo -e "$SENSITIVE_IN_LOGS")" \
            "Sanitize log output to strip sensitive parameters. Use log filtering or redaction."
    else
        echo "✅ No sensitive data patterns found in recent log files." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi


}
