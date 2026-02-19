scan_section_10() {
    local REPORT_FILE="$1"
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


}
