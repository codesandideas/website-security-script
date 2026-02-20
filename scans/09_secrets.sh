scan_section_9() {
    local REPORT_FILE="$1"
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
            grep -v "node_modules\|vendor/\|venv/\|\.env\.example\|\.env\.sample" || true)
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
        2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/\|dist/\|\.example\|\.sample\|\.md\|test\|composer\.json\|package\.json\|package-lock\.json" | filter_results | head -30 || true)

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


}
