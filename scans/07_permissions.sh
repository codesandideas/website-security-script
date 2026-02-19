scan_section_7() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 7: FILE PERMISSIONS AUDIT
    # ══════════════════════════════════════════════════════════════════════════════
    log "Auditing file permissions..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 7. File Permissions Audit

EOF

    WORLD_WRITABLE=$(find "$SCAN_DIR" -type f -perm -o+w 2>/dev/null | \
        grep -v "node_modules\|/cache/\|vendor/\|\.git/" | head -30 || true)

    if [[ -n "$WORLD_WRITABLE" ]]; then
        finding "high" "World-Writable Files Found" \
            "Files writable by any user on the system." \
            "$WORLD_WRITABLE" \
            "Fix: \`find $SCAN_DIR -type f -perm -o+w -exec chmod o-w {} \\;\`"
    else
        echo "✅ No world-writable files." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi

    WORLD_WRITABLE_DIRS=$(find "$SCAN_DIR" -type d -perm -o+w 2>/dev/null | \
        grep -v "node_modules\|/cache/\|vendor/\|\.git/" | head -20 || true)

    if [[ -n "$WORLD_WRITABLE_DIRS" ]]; then
        finding "high" "World-Writable Directories Found" \
            "Directories writable by any user." \
            "$WORLD_WRITABLE_DIRS" \
            "Fix: \`find $SCAN_DIR -type d -perm -o+w -exec chmod o-w {} \\;\`"
    else
        echo "✅ No world-writable directories." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
    fi

    SUID_FILES=$(find "$SCAN_DIR" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10 || true)
    if [[ -n "$SUID_FILES" ]]; then
        finding "high" "SUID/SGID Files in Web Directory" \
            "Can be exploited for privilege escalation." \
            "$SUID_FILES" \
            "Remove: \`chmod u-s,g-s <file>\`."
    fi


}
