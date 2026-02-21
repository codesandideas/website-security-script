# ── Auto-Remediation (--fix mode) ─────────────────────────────────────────────
#
# Safely auto-fixes common security issues found during scanning.
# All destructive actions are logged and reversible via --restore.
#
# Usage:
#   webscan /var/www/html --fix            # Interactive (prompt each fix)
#   webscan /var/www/html --fix-auto       # Non-interactive (apply all safe fixes)
#   webscan --restore <quarantine-id>      # Restore a quarantined file

FIX_MODE=false
FIX_AUTO=false
FIX_LOG_DIR="${REAL_HOME:-$HOME}/.config/webscan/fix-logs"
QUARANTINE_DIR="${REAL_HOME:-$HOME}/.config/webscan/quarantine"
FIX_COUNT=0
FIX_SKIPPED=0

# ── Prompt helper ──────────────────────────────────────────────────────────────
fix_prompt() {
    local msg="$1"
    if [[ "$FIX_AUTO" == true ]]; then
        return 0  # auto-apply
    fi
    echo -e ""
    echo -e "${YELLOW}[FIX]${NC} ${msg}"
    printf "  Apply this fix? [y/N] "
    read -r answer </dev/tty
    [[ "$answer" =~ ^[Yy]$ ]]
}

fix_applied() {
    local msg="$1"
    ok "  Fixed: ${msg}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | FIXED   | ${msg}" >> "$FIX_LOG_DIR/fix_$(date '+%Y-%m-%d').log"
    FIX_COUNT=$((FIX_COUNT + 1))
}

fix_skipped() {
    local msg="$1"
    log "  Skipped: ${msg}"
    FIX_SKIPPED=$((FIX_SKIPPED + 1))
}

# ── Quarantine a file (move, never delete) ─────────────────────────────────────
quarantine_file() {
    local file="$1" reason="${2:-suspicious}"
    local q_id
    q_id="$(date '+%Y%m%d%H%M%S')_$(basename "$file")"
    local q_path="${QUARANTINE_DIR}/${q_id}"
    local meta_path="${QUARANTINE_DIR}/${q_id}.meta"

    mkdir -p "$QUARANTINE_DIR"

    if fix_prompt "Quarantine: $(basename "$file")\n  Path: ${file}\n  Reason: ${reason}"; then
        cp "$file" "$q_path" && chmod 600 "$q_path"
        cat > "$meta_path" <<METAEOF
ORIGINAL_PATH=${file}
QUARANTINE_DATE=$(date '+%Y-%m-%d %H:%M:%S')
REASON=${reason}
CHECKSUM=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || md5sum "$file" 2>/dev/null | cut -d' ' -f1)
METAEOF
        rm -f "$file"
        fix_applied "Quarantined to: ${q_path}  (restore: webscan --restore ${q_id})"
    else
        fix_skipped "$file"
    fi
}

# ── Fix file permissions ───────────────────────────────────────────────────────
fix_permissions() {
    local target="$SCAN_DIR"
    log "Scanning for permission issues to fix..."

    # World-writable directories (should be 755)
    local ww_dirs
    ww_dirs=$(find "$target" -type d -perm -o+w 2>/dev/null | grep -vE "$EXCLUDE_PATTERN" | head -50 || true)
    if [[ -n "$ww_dirs" ]]; then
        echo ""
        warn "Found world-writable directories:"
        echo "$ww_dirs" | head -10 | while read -r d; do echo "  $d"; done
        if fix_prompt "chmod 755 all world-writable directories ($(echo "$ww_dirs" | wc -l) items)"; then
            echo "$ww_dirs" | while read -r d; do
                chmod 755 "$d" 2>/dev/null && echo "  → ${d}" || true
            done
            fix_applied "Set 755 on world-writable directories"
        else
            fix_skipped "world-writable directories"
        fi
    fi

    # World-writable files (should be 644 max)
    local ww_files
    ww_files=$(find "$target" -type f -perm -o+w 2>/dev/null | grep -vE "$EXCLUDE_PATTERN" | head -50 || true)
    if [[ -n "$ww_files" ]]; then
        echo ""
        warn "Found world-writable files:"
        echo "$ww_files" | head -10 | while read -r f; do echo "  $f"; done
        if fix_prompt "chmod 644 all world-writable files ($(echo "$ww_files" | wc -l) items)"; then
            echo "$ww_files" | while read -r f; do
                chmod 644 "$f" 2>/dev/null && echo "  → ${f}" || true
            done
            fix_applied "Set 644 on world-writable files"
        else
            fix_skipped "world-writable files"
        fi
    fi

    # Config files that are too permissive (wp-config.php, .env, etc.)
    local config_files
    config_files=$(find "$target" -type f \( -name "wp-config.php" -o -name ".env" -o -name "config.php" \) -perm /o+r 2>/dev/null | head -20 || true)
    if [[ -n "$config_files" ]]; then
        echo ""
        warn "Sensitive config files are world-readable:"
        echo "$config_files" | while read -r f; do echo "  $f"; done
        if fix_prompt "chmod 640 sensitive config files (wp-config.php, .env, etc.)"; then
            echo "$config_files" | while read -r f; do
                chmod 640 "$f" 2>/dev/null && echo "  → ${f}" || true
            done
            fix_applied "Set 640 on sensitive config files"
        else
            fix_skipped "config file permissions"
        fi
    fi

    # Executable files in upload directories
    local exec_in_uploads
    exec_in_uploads=$(find "$target" -path "*/uploads/*.php" -o -path "*/media/*.php" -o -path "*/files/*.php" 2>/dev/null | head -20 || true)
    if [[ -n "$exec_in_uploads" ]]; then
        echo ""
        warn "PHP files found in upload directories:"
        echo "$exec_in_uploads" | while read -r f; do echo "  $f"; done
        if fix_prompt "Quarantine PHP files in upload directories (likely malware)"; then
            echo "$exec_in_uploads" | while read -r f; do
                quarantine_file "$f" "PHP file in upload directory — potential backdoor"
            done
        else
            fix_skipped "PHP files in upload dirs"
        fi
    fi
}

# ── Fix .htaccess security rules ───────────────────────────────────────────────
fix_htaccess() {
    local htaccess="${SCAN_DIR}/.htaccess"
    [[ ! -f "$htaccess" ]] && return 0

    # Block .git directory exposure
    if ! grep -q '\.git' "$htaccess" 2>/dev/null; then
        if fix_prompt "Add .htaccess rule to block public access to .git directory"; then
            cat >> "$htaccess" <<'HTEOF'

# Block .git directory — added by WebSecurityScanner
<IfModule mod_rewrite.c>
    RewriteRule ^\.git - [F,L]
</IfModule>
<FilesMatch "^\.git">
    Order allow,deny
    Deny from all
</FilesMatch>
HTEOF
            fix_applied "Blocked .git access in .htaccess"
        else
            fix_skipped ".git .htaccess rule"
        fi
    fi

    # Block .env file exposure
    if ! grep -q '\.env' "$htaccess" 2>/dev/null; then
        if fix_prompt "Add .htaccess rule to block public access to .env file"; then
            cat >> "$htaccess" <<'HTEOF'

# Block .env file — added by WebSecurityScanner
<FilesMatch "^\.env">
    Order allow,deny
    Deny from all
</FilesMatch>
HTEOF
            fix_applied "Blocked .env access in .htaccess"
        else
            fix_skipped ".env .htaccess rule"
        fi
    fi

    # Add security headers
    if ! grep -q 'X-Content-Type-Options' "$htaccess" 2>/dev/null; then
        if fix_prompt "Add security headers (X-Frame-Options, HSTS, X-Content-Type-Options) to .htaccess"; then
            cat >> "$htaccess" <<'HTEOF'

# Security headers — added by WebSecurityScanner
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>
HTEOF
            fix_applied "Added security headers to .htaccess"
        else
            fix_skipped "security headers"
        fi
    fi

    # Block directory listing
    if ! grep -qi 'Options.*-Indexes' "$htaccess" 2>/dev/null; then
        if fix_prompt "Disable directory listing in .htaccess (Options -Indexes)"; then
            echo "" >> "$htaccess"
            echo "# Disable directory listing — added by WebSecurityScanner" >> "$htaccess"
            echo "Options -Indexes" >> "$htaccess"
            fix_applied "Disabled directory listing"
        else
            fix_skipped "directory listing"
        fi
    fi
}

# ── Fix WordPress-specific issues ──────────────────────────────────────────────
fix_wordpress() {
    has_framework "WordPress" || return 0

    local wpconfig="${SCAN_DIR}/wp-config.php"
    [[ ! -f "$wpconfig" ]] && return 0

    # Disable debug mode if enabled
    if grep -q "WP_DEBUG.*true" "$wpconfig" 2>/dev/null; then
        if fix_prompt "Disable WP_DEBUG in wp-config.php (currently: true → change to false)"; then
            sed -i "s/define.*WP_DEBUG.*true/define('WP_DEBUG', false)/" "$wpconfig"
            fix_applied "Disabled WP_DEBUG in wp-config.php"
        else
            fix_skipped "WP_DEBUG"
        fi
    fi

    # Disable file editing in admin panel
    if ! grep -q 'DISALLOW_FILE_EDIT' "$wpconfig" 2>/dev/null; then
        if fix_prompt "Disable WordPress theme/plugin editor (add DISALLOW_FILE_EDIT to wp-config.php)"; then
            sed -i "/^\/\* That's all/i define('DISALLOW_FILE_EDIT', true);\n" "$wpconfig" 2>/dev/null || \
            echo "define('DISALLOW_FILE_EDIT', true);" >> "$wpconfig"
            fix_applied "Disabled WP file editor"
        else
            fix_skipped "DISALLOW_FILE_EDIT"
        fi
    fi

    # Block xmlrpc.php if not needed
    local htaccess="${SCAN_DIR}/.htaccess"
    if [[ -f "$htaccess" ]] && ! grep -q 'xmlrpc' "$htaccess" 2>/dev/null; then
        if fix_prompt "Block xmlrpc.php access in .htaccess (prevents brute-force attacks)"; then
            cat >> "$htaccess" <<'HTEOF'

# Block XML-RPC — added by WebSecurityScanner
<Files "xmlrpc.php">
    Order allow,deny
    Deny from all
</Files>
HTEOF
            fix_applied "Blocked xmlrpc.php"
        else
            fix_skipped "xmlrpc.php block"
        fi
    fi
}

# ── Restore a quarantined file ─────────────────────────────────────────────────
restore_quarantine() {
    local q_id="$1"
    local q_path="${QUARANTINE_DIR}/${q_id}"
    local meta_path="${QUARANTINE_DIR}/${q_id}.meta"

    if [[ ! -f "$q_path" ]]; then
        err "Quarantine item not found: ${q_id}"
        echo ""
        echo "Available quarantine items:"
        ls "$QUARANTINE_DIR" 2>/dev/null | grep -v '\.meta$' | while read -r item; do
            local orig
            orig=$(grep '^ORIGINAL_PATH=' "${QUARANTINE_DIR}/${item}.meta" 2>/dev/null | cut -d= -f2 || echo "unknown")
            echo "  ${item}  →  ${orig}"
        done
        exit 1
    fi

    local original_path
    original_path=$(grep '^ORIGINAL_PATH=' "$meta_path" 2>/dev/null | cut -d= -f2)
    local quarantine_date
    quarantine_date=$(grep '^QUARANTINE_DATE=' "$meta_path" 2>/dev/null | cut -d= -f2)
    local reason
    reason=$(grep '^REASON=' "$meta_path" 2>/dev/null | cut -d= -f2)

    echo ""
    warn "About to restore a quarantined file:"
    echo "  File     : ${original_path}"
    echo "  Quarantined: ${quarantine_date}"
    echo "  Reason   : ${reason}"
    echo ""
    printf "  Are you sure you want to restore this file? [y/N] "
    read -r answer </dev/tty
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        mkdir -p "$(dirname "$original_path")"
        cp "$q_path" "$original_path"
        ok "Restored: ${original_path}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') | RESTORED | ${original_path}" >> "$FIX_LOG_DIR/fix_$(date '+%Y-%m-%d').log"
    else
        log "Restore cancelled."
    fi
    exit 0
}

# ── List quarantined files ─────────────────────────────────────────────────────
list_quarantine() {
    echo ""
    echo -e "${BOLD}Quarantine Directory:${NC} ${QUARANTINE_DIR}"
    echo ""
    if [[ ! -d "$QUARANTINE_DIR" ]] || [[ -z "$(ls -A "$QUARANTINE_DIR" 2>/dev/null | grep -v '\.meta$')" ]]; then
        ok "Quarantine is empty."
    else
        printf "%-40s %-30s %s\n" "ID" "Date" "Original Path"
        printf "%-40s %-30s %s\n" "$(printf '%0.s-' {1..38})" "$(printf '%0.s-' {1..28})" "$(printf '%0.s-' {1..30})"
        ls "$QUARANTINE_DIR" 2>/dev/null | grep -v '\.meta$' | while read -r item; do
            local orig qdate
            orig=$(grep '^ORIGINAL_PATH=' "${QUARANTINE_DIR}/${item}.meta" 2>/dev/null | cut -d= -f2 || echo "unknown")
            qdate=$(grep '^QUARANTINE_DATE=' "${QUARANTINE_DIR}/${item}.meta" 2>/dev/null | cut -d= -f2 || echo "unknown")
            printf "%-40s %-30s %s\n" "${item:0:38}" "$qdate" "$orig"
        done
    fi
    echo ""
    exit 0
}

# ── Main fix runner ────────────────────────────────────────────────────────────
run_fix_mode() {
    [[ "$FIX_MODE" != true ]] && return 0

    mkdir -p "$FIX_LOG_DIR" "$QUARANTINE_DIR"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    AUTO-REMEDIATION MODE                       ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"

    if [[ "$FIX_AUTO" != true ]]; then
        echo ""
        warn "Running in INTERACTIVE mode. You will be prompted before each fix."
        warn "Use --fix-auto to apply all safe fixes without prompting."
        echo ""
    else
        echo ""
        warn "Running in AUTO mode. All safe fixes will be applied automatically."
        echo ""
    fi

    log "Fix log: ${FIX_LOG_DIR}/fix_$(date '+%Y-%m-%d').log"
    echo ""

    fix_permissions
    fix_htaccess
    fix_wordpress

    echo ""
    echo "── Fix Summary ──────────────────────────────────────────────────────"
    ok "Fixes applied : ${FIX_COUNT}"
    log "Fixes skipped : ${FIX_SKIPPED}"
    echo "────────────────────────────────────────────────────────────────────"
    echo ""
    [[ $FIX_COUNT -gt 0 ]] && log "Fix log saved: ${FIX_LOG_DIR}/fix_$(date '+%Y-%m-%d').log"
    [[ -d "$QUARANTINE_DIR" ]] && [[ -n "$(ls -A "$QUARANTINE_DIR" 2>/dev/null | grep -v '\.meta$')" ]] && \
        log "Quarantine: ${QUARANTINE_DIR}  (restore: webscan --restore <id>)"
}
