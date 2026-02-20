scan_section_4() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 4: FILE INTEGRITY & ANOMALIES
    # ══════════════════════════════════════════════════════════════════════════════
    log "Checking file integrity..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 4. File Integrity & Anomalies

Checking for recently created files, symlink attacks, and anomalous patterns.

EOF

    # ── 4a. Recently created executable files (last 7 days) ─────────────────────
    RECENT_EXEC=$(find "$SCAN_DIR" -type f \( \
        -name "*.php" -o -name "*.js" -o -name "*.py" -o -name "*.rb" \
        -o -name "*.pl" -o -name "*.cgi" -o -name "*.sh" \
        \) -ctime -7 2>/dev/null | \
        grep -v "node_modules\|vendor/\|\.git/\|cache\|venv/\|__pycache__\|dist/\|build/" | filter_results | head -50 || true)

    if [[ -n "$RECENT_EXEC" ]]; then
        finding "medium" "Executable Files Created/Changed in Last 7 Days" \
            "These executable files were recently created or modified. Review if unexpected." \
            "$RECENT_EXEC" \
            "Cross-reference with recent deployments. Unexpected new files may indicate compromise."
    else
        echo "✅ No newly created executable files in the last 7 days." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 4b. Symlinks pointing outside web root ───────────────────────────────────
    SYMLINKS=$(find "$SCAN_DIR" -type l 2>/dev/null | head -20 || true)
    if [[ -n "$SYMLINKS" ]]; then
        EXTERNAL_SYMLINKS=""
        while IFS= read -r link; do
            TARGET=$(readlink -f "$link" 2>/dev/null || echo "")
            if [[ -n "$TARGET" && "$TARGET" != "$SCAN_DIR"* ]]; then
                EXTERNAL_SYMLINKS+="$link -> $TARGET"$'\n'
            fi
        done <<< "$SYMLINKS"

        if [[ -n "$EXTERNAL_SYMLINKS" ]]; then
            finding "high" "Symlinks Pointing Outside Web Root" \
                "Symbolic links pointing outside the web root could expose sensitive system files." \
                "$EXTERNAL_SYMLINKS" \
                "Remove symlinks that point outside the web root unless intentionally configured."
        fi
    fi


}
