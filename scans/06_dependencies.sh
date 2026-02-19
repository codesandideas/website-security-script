scan_section_6() {
    local REPORT_FILE="$1"
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


}
