scan_section_3() {
    local REPORT_FILE="$1"
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
        B64_RESULTS=$(grep -rlEi "$B64_REGEX" "$SCAN_DIR" \
            --include="*.php" --include="*.inc" \
            2>/dev/null | grep -v "node_modules\|vendor/" | filter_results | head -50 || true)

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
        JS_OBFUSC_RESULTS=$(grep -rlEi "$JS_OBFUSC_REGEX" "$SCAN_DIR" \
            --include="*.js" --include="*.mjs" 2>/dev/null | \
            grep -v "node_modules\|\.min\.js\|dist/\|build/" | filter_results | head -30 || true)

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
    HEX_RESULTS=$(grep -rlP '\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}' "$SCAN_DIR" \
        --include="*.php" --include="*.js" --include="*.py" \
        2>/dev/null | grep -v "node_modules\|vendor/\|\.min\." | filter_results | head -30 || true)

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
        OBFUSC_RESULTS=$(grep -rlEi "$OBFUSC_REGEX" "$SCAN_DIR" \
            --include="*.php" 2>/dev/null | grep -v "node_modules\|vendor/" | filter_results | head -30 || true)

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


}
