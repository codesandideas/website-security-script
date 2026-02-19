scan_section_8() {
    local REPORT_FILE="$1"
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


}
