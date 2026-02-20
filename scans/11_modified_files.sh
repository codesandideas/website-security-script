scan_section_11() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 11: RECENTLY MODIFIED FILES
    # ══════════════════════════════════════════════════════════════════════════════
    log "Checking recently modified files..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 11. Recently Modified Files

EOF

    RECENT_MODIFIED=$(find "$SCAN_DIR" -type f \( \
        -name "*.php" -o -name "*.js" -o -name "*.py" -o -name "*.rb" \
        -o -name "*.html" -o -name "*.sh" \
        \) -mtime -3 2>/dev/null | \
        grep -v "node_modules\|vendor/\|\.git/\|cache\|venv/\|__pycache__\|dist/\|build/\|\.next/" | \
        filter_results | sort | head -50 || true)

    if [[ -n "$RECENT_MODIFIED" ]]; then
        echo "Files modified in the last 3 days:" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "$RECENT_MODIFIED" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "> Review if no recent deployments were performed." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    else
        echo "✅ No source files modified in the last 3 days." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi


}
