scan_section_13() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 13: DATABASE SECURITY
    # ══════════════════════════════════════════════════════════════════════════════
    log "Checking database security..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 13. Database Security

Checking for exposed database files, open ports, default credentials, and unencrypted connections.

EOF

    # ── 13a. SQL Dumps in Web Root ────────────────────────────────────────────────
    log "Checking for SQL dumps in web root..."

    SQL_DUMPS=$(find "$SCAN_DIR" -type f \( \
        -name "*.sql" -o -name "*.sql.gz" -o -name "*.sql.bz2" \
        -o -name "*.dump" -o -name "*.sql.zip" -o -name "*.sqlite" \
        -o -name "*.db" \
        \) 2>/dev/null | \
        grep -v "node_modules\|vendor/\|\.git/\|venv/\|__pycache__" | head -20 || true)

    if [[ -n "$SQL_DUMPS" ]]; then
        finding "critical" "Database Dumps Found in Web Root" \
            "SQL dump or database files were found in the web-accessible directory. These may contain sensitive data." \
            "$SQL_DUMPS" \
            "Move database dumps outside the web root immediately. Delete any unnecessary backup files."
    else
        echo "✅ No database dump files found in web root." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 13b. Database Port Exposed ────────────────────────────────────────────────
    log "Checking for exposed database ports..."

    DB_PORTS_EXPOSED=""
    if command -v ss &>/dev/null; then
        DB_PORTS_EXPOSED=$(ss -tlnp 2>/dev/null | grep -E ':(3306|5432|27017|6379|1433)\s' | grep -E '0\.0\.0\.0|::|\*' || true)
    elif command -v netstat &>/dev/null; then
        DB_PORTS_EXPOSED=$(netstat -tlnp 2>/dev/null | grep -E ':(3306|5432|27017|6379|1433)\s' | grep -E '0\.0\.0\.0|::|\*' || true)
    fi

    if [[ -n "$DB_PORTS_EXPOSED" ]]; then
        finding "critical" "Database Ports Exposed to All Interfaces" \
            "Database services are listening on all network interfaces (0.0.0.0), making them accessible from external networks." \
            "$DB_PORTS_EXPOSED" \
            "Bind database services to 127.0.0.1 only. Use firewall rules to restrict access."
    else
        echo "✅ No database ports exposed on all interfaces." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 13c. Default/Root Database Credentials ────────────────────────────────────
    log "Checking for default database credentials..."

    DB_CRED_ISSUES=""
    # Check common config files for root user or empty passwords
    for cfg_file in $(find "$SCAN_DIR" -maxdepth 3 -type f \( \
        -name "wp-config.php" -o -name ".env" -o -name "settings.py" \
        -o -name "database.yml" -o -name "database.php" -o -name "config.php" \
        -o -name "db.php" -o -name "application.properties" \
        \) 2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/" | head -20); do

        # Check for root user in DB config
        ROOT_DB=$(grep -Ein "DB_USER.*root|'username'.*root|DB_USERNAME.*root|user.*=.*root" "$cfg_file" 2>/dev/null | grep -iv 'rootdir\|webroot\|docroot\|app_root' || true)
        if [[ -n "$ROOT_DB" ]]; then
            DB_CRED_ISSUES="$DB_CRED_ISSUES\n$cfg_file:\n$ROOT_DB"
        fi

        # Check for empty passwords
        EMPTY_PASS=$(grep -Ein "DB_PASSWORD\s*=\s*$|DB_PASSWORD\s*=\s*['\"]'*['\"]|'password'\s*=>\s*''|DATABASE_PASSWORD\s*=\s*$" "$cfg_file" 2>/dev/null || true)
        if [[ -n "$EMPTY_PASS" ]]; then
            DB_CRED_ISSUES="$DB_CRED_ISSUES\n$cfg_file:\n$EMPTY_PASS"
        fi
    done

    if [[ -n "$DB_CRED_ISSUES" ]]; then
        finding "critical" "Default or Weak Database Credentials" \
            "Configuration files contain root database user or empty passwords." \
            "$(echo -e "$DB_CRED_ISSUES")" \
            "Use a dedicated database user with limited privileges. Never use root for application connections. Set strong passwords."
    else
        echo "✅ No default or empty database credentials detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 13d. Unencrypted Database Connections ─────────────────────────────────────
    log "Checking for unencrypted database connections..."

    DB_NO_SSL=""
    for cfg_file in $(find "$SCAN_DIR" -maxdepth 3 -type f \( \
        -name "wp-config.php" -o -name ".env" -o -name "settings.py" \
        -o -name "database.yml" -o -name "database.php" -o -name "config.php" \
        -o -name "application.properties" \
        \) 2>/dev/null | grep -v "node_modules\|vendor/\|\.git/\|venv/" | head -20); do

        # Check if file has DB config but no SSL settings
        HAS_DB=$(grep -Ei 'DB_HOST|DATABASE_URL|database.*host|jdbc:' "$cfg_file" 2>/dev/null || true)
        HAS_SSL=$(grep -Ei 'DB_SSL|MYSQL_SSL|sslmode|ssl_ca|ssl_cert|require_ssl|useSSL' "$cfg_file" 2>/dev/null || true)

        if [[ -n "$HAS_DB" && -z "$HAS_SSL" ]]; then
            # Skip if DB host is localhost/127.0.0.1/::1 — uses Unix socket, no network exposure
            IS_LOCAL=$(grep -Ei 'DB_HOST\s*=\s*["\x27]?(localhost|127\.0\.0\.1|::1)["\x27]?' "$cfg_file" 2>/dev/null || true)
            if [[ -z "$IS_LOCAL" ]]; then
                # Also check DATABASE_URL for localhost
                IS_LOCAL_URL=$(grep -Ei 'DATABASE_URL.*@(localhost|127\.0\.0\.1|::1)[:/]' "$cfg_file" 2>/dev/null || true)
            fi
            if [[ -z "$IS_LOCAL" && -z "$IS_LOCAL_URL" ]]; then
                DB_NO_SSL="$DB_NO_SSL\n$cfg_file: Database connection configured without SSL parameters"
            fi
        fi
    done

    if [[ -n "$DB_NO_SSL" ]]; then
        finding "high" "Unencrypted Database Connections" \
            "Database configuration files do not specify SSL/TLS encryption for database connections." \
            "$(echo -e "$DB_NO_SSL")" \
            "Enable SSL/TLS for database connections. Add SSL certificates and require encrypted connections."
    else
        echo "✅ No unencrypted database connection issues detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi


}
