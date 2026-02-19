scan_section_2() {
    local REPORT_FILE="$1"
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


}
