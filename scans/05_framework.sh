scan_section_5() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 5: FRAMEWORK-SPECIFIC AUDIT
    # ══════════════════════════════════════════════════════════════════════════════
    log "Running framework-specific audits..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 5. Framework-Specific Audit

Configuration and security checks tailored to the detected framework(s).

EOF

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ WORDPRESS                                                          │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "wordpress"; then
        echo "### WordPress Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        WP_CONFIG="$SCAN_DIR/wp-config.php"

        WP_VER_FILE="$SCAN_DIR/wp-includes/version.php"
        if [[ -f "$WP_VER_FILE" ]]; then
            WP_VERSION=$(grep '^\$wp_version\s*=' "$WP_VER_FILE" 2>/dev/null | sed "s/.*'\(.*\)'.*/\1/" || echo "unknown")
            echo "**WordPress Version:** \`$WP_VERSION\`" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"

            WP_MAJOR=$(echo "$WP_VERSION" | cut -d. -f1 | tr -dc '0-9')
            WP_MINOR=$(echo "$WP_VERSION" | cut -d. -f2 | tr -dc '0-9')
            WP_MAJOR=${WP_MAJOR:-0}; WP_MINOR=${WP_MINOR:-0}
            if [[ "$WP_MAJOR" -lt 6 ]] || { [[ "$WP_MAJOR" -eq 6 ]] && [[ "$WP_MINOR" -lt 4 ]]; }; then
                finding "high" "Outdated WordPress Version ($WP_VERSION)" \
                    "This WordPress version may contain known security vulnerabilities." \
                    "" \
                    "Update to the latest WordPress version. Back up the database first."
            fi
        fi

        if [[ -f "$WP_CONFIG" ]]; then
            # Debug mode
            if grep -qEi "define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
                finding "high" "WordPress Debug Mode Enabled" \
                    "WP_DEBUG is true — error information is exposed." \
                    "" \
                    "Set WP_DEBUG to false in production."
            fi

            # File editor
            if ! grep -qEi "define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
                finding "medium" "WordPress File Editor Not Disabled" \
                    "The built-in file editor allows admin users to edit PHP files from the dashboard." \
                    "" \
                    "Add \`define('DISALLOW_FILE_EDIT', true);\` to wp-config.php."
            fi

            # Security keys
            DEFAULT_KEYS=$(grep -cE "put your unique phrase here" "$WP_CONFIG" 2>/dev/null | head -1)
            DEFAULT_KEYS=${DEFAULT_KEYS:-0}
            if [[ "$DEFAULT_KEYS" -gt 0 ]]; then
                finding "critical" "Default WordPress Security Keys" \
                    "Security keys are still default — session security is severely weakened." \
                    "" \
                    "Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/"
            fi

            # Table prefix
            if grep -qEi "\\\$table_prefix\s*=\s*['\"]wp_['\"]" "$WP_CONFIG" 2>/dev/null; then
                finding "low" "Default Database Table Prefix (wp_)" \
                    "Default prefix makes SQL injection attacks easier to target." \
                    "" \
                    "Consider a custom table prefix."
            fi

            # SSL
            if ! grep -qEi "define\s*\(\s*['\"]FORCE_SSL_ADMIN['\"]\s*,\s*true" "$WP_CONFIG" 2>/dev/null; then
                finding "medium" "SSL Not Forced for WordPress Admin" \
                    "FORCE_SSL_ADMIN is not enabled." \
                    "" \
                    "Add \`define('FORCE_SSL_ADMIN', true);\`"
            fi

            # DB root
            DB_USER=$(grep "DB_USER" "$WP_CONFIG" 2>/dev/null | sed "s/.*['\"]DB_USER['\"].*['\"]\\(.*\\)['\"].*/\\1/" | head -1 || echo "")
            if [[ "$DB_USER" == "root" ]]; then
                finding "critical" "WordPress Using Root Database User" \
                    "Connecting as root is extremely dangerous." \
                    "" \
                    "Create a dedicated database user."
            fi
        fi

        # Plugin inventory
        PLUGIN_DIR="$SCAN_DIR/wp-content/plugins"
        if [[ -d "$PLUGIN_DIR" ]]; then
            echo "#### Installed Plugins" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
            echo "| Plugin | Version | Notes |" >> "$REPORT_FILE"
            echo "|--------|---------|-------|" >> "$REPORT_FILE"

            PC=0
            for PD in "$PLUGIN_DIR"/*/; do
                [[ ! -d "$PD" ]] && continue
                PN=$(basename "$PD"); PC=$((PC + 1)); PV="Unknown"
                for PF in "$PD"*.php; do
                    [[ -f "$PF" ]] || continue
                    V=$(grep -i "Version:" "$PF" 2>/dev/null | head -1 | sed 's/.*Version:\s*//i' | tr -d '[:space:]')
                    [[ -n "$V" ]] && PV="$V" && break
                done
                STATUS="—"
                case "$PN" in
                    revslider|revolution-slider) STATUS="⚠️ Historically vulnerable" ;;
                    wp-file-manager) STATUS="⚠️ Check for CVEs" ;;
                    wpgateway) STATUS="🔴 Known backdoor vector" ;;
                esac
                echo "| $PN | $PV | $STATUS |" >> "$REPORT_FILE"
            done
            echo "" >> "$REPORT_FILE"
            echo "**Total:** $PC plugins" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi

        # WP-VCD
        THEME_DIR="$SCAN_DIR/wp-content/themes"
        if [[ -d "$THEME_DIR" ]]; then
            WPVCD=$(grep -rl "wp-vcd\|class\.theme-modules\.php" "$THEME_DIR" --include="*.php" 2>/dev/null || true)
            if [[ -n "$WPVCD" ]]; then
                finding "critical" "WP-VCD Malware in Themes" \
                    "WP-VCD malware detected in theme files." \
                    "$WPVCD" \
                    "Delete infected themes and reinstall clean copies."
            fi
        fi

        # Uploads protection
        if [[ -d "$SCAN_DIR/wp-content/uploads" && ! -f "$SCAN_DIR/wp-content/uploads/.htaccess" ]]; then
            finding "high" "No .htaccess Protection in WordPress Uploads" \
                "The uploads directory has no .htaccess to block PHP execution." \
                "" \
                "Create .htaccess in wp-content/uploads/ with rules to deny PHP execution."
        fi

        # XML-RPC
        if [[ -f "$SCAN_DIR/xmlrpc.php" ]]; then
            XMLRPC_BLOCKED=false
            [[ -f "$SCAN_DIR/.htaccess" ]] && grep -qi "xmlrpc" "$SCAN_DIR/.htaccess" 2>/dev/null && XMLRPC_BLOCKED=true
            if [[ "$XMLRPC_BLOCKED" == false ]]; then
                finding "medium" "WordPress XML-RPC Enabled" \
                    "xmlrpc.php is accessible — can be used for brute force amplification." \
                    "" \
                    "Block XML-RPC if not needed."
            fi
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ LARAVEL                                                            │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "laravel"; then
        echo "### Laravel Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        ENV_FILE="$SCAN_DIR/.env"
        if [[ -f "$ENV_FILE" ]]; then
            if grep -qEi "^APP_DEBUG\s*=\s*true" "$ENV_FILE" 2>/dev/null; then
                finding "critical" "Laravel APP_DEBUG is Enabled" \
                    "Debug mode exposes stack traces, environment variables, and database credentials." \
                    "" \
                    "Set APP_DEBUG=false in .env for production."
            else
                echo "✅ APP_DEBUG is disabled." >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
            fi

            if grep -qEi "^APP_ENV\s*=\s*(local|development|testing)" "$ENV_FILE" 2>/dev/null; then
                finding "high" "Laravel APP_ENV Not Set to Production" \
                    "Application environment is not 'production'." \
                    "" \
                    "Set APP_ENV=production."
            fi

            APP_KEY=$(grep "^APP_KEY=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
            if [[ -z "$APP_KEY" || "$APP_KEY" == "SomeRandomString" || "$APP_KEY" == "base64:" ]]; then
                finding "critical" "Laravel APP_KEY Not Set" \
                    "Encryption key is missing — session data and encrypted values are insecure." \
                    "" \
                    "Run \`php artisan key:generate\`."
            fi

            DB_USER=$(grep "^DB_USERNAME=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
            if [[ "$DB_USER" == "root" ]]; then
                finding "critical" "Laravel Using Root Database User" \
                    "Connecting as root is dangerous." \
                    "" \
                    "Create a dedicated database user."
            fi
        fi

        if [[ -d "$SCAN_DIR/storage/logs" ]]; then
            LOG_FILES=$(find "$SCAN_DIR/storage/logs" -name "*.log" -size +0c 2>/dev/null | head -5 || true)
            if [[ -n "$LOG_FILES" ]]; then
                finding "medium" "Laravel Log Files Present" \
                    "Log files may contain sensitive data. Ensure storage/ is not publicly accessible." \
                    "$LOG_FILES" \
                    "Block public access to the storage/ directory."
            fi
        fi

        if [[ -f "$SCAN_DIR/app/Http/Kernel.php" ]]; then
            if ! grep -q "VerifyCsrfToken" "$SCAN_DIR/app/Http/Kernel.php" 2>/dev/null; then
                finding "high" "Laravel CSRF Protection May Be Disabled" \
                    "VerifyCsrfToken middleware not found in Kernel.php." \
                    "" \
                    "Ensure CSRF protection is active."
            fi
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ DRUPAL                                                             │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "drupal"; then
        echo "### Drupal Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        if [[ -f "$SCAN_DIR/core/lib/Drupal.php" ]]; then
            DRUPAL_VER=$(grep "const VERSION" "$SCAN_DIR/core/lib/Drupal.php" 2>/dev/null | sed "s/.*'\(.*\)'.*/\1/" || echo "unknown")
            echo "**Drupal Version:** \`$DRUPAL_VER\`" >> "$REPORT_FILE"; echo "" >> "$REPORT_FILE"
        fi

        SETTINGS_FILE="$SCAN_DIR/sites/default/settings.php"
        if [[ -f "$SETTINGS_FILE" ]]; then
            SP=$(stat -c '%a' "$SETTINGS_FILE" 2>/dev/null || echo "unknown")
            if [[ "$SP" != "444" && "$SP" != "440" && "$SP" != "400" ]]; then
                finding "high" "Drupal settings.php Permissive ($SP)" \
                    "settings.php contains database credentials and should be read-only." \
                    "" \
                    "Run \`chmod 440 sites/default/settings.php\`."
            fi
            if ! grep -q "trusted_host_patterns" "$SETTINGS_FILE" 2>/dev/null; then
                finding "medium" "Drupal Trusted Host Patterns Not Set" \
                    "Vulnerable to HTTP Host header attacks." \
                    "" \
                    "Configure \$settings['trusted_host_patterns'] in settings.php."
            fi
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ JOOMLA                                                             │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "joomla"; then
        echo "### Joomla Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        JOOMLA_CONFIG="$SCAN_DIR/configuration.php"
        if [[ -f "$JOOMLA_CONFIG" ]]; then
            if grep -qEi "error_reporting\s*=\s*['\"]?maximum\|error_reporting\s*=\s*['\"]?development" "$JOOMLA_CONFIG" 2>/dev/null; then
                finding "high" "Joomla Error Reporting Set to Maximum" \
                    "Detailed errors exposed to visitors." \
                    "" \
                    "Set error_reporting to 'none' in Global Configuration."
            fi

            DB_USER=$(grep -Ei "user\s*=" "$JOOMLA_CONFIG" 2>/dev/null | head -1 | sed "s/.*['\"]\\(.*\\)['\"].*/\\1/" || echo "")
            if [[ "$DB_USER" == "root" ]]; then
                finding "critical" "Joomla Using Root Database User" \
                    "Connecting as root is extremely dangerous." \
                    "" \
                    "Create a dedicated database user."
            fi
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ NODE.JS / EXPRESS / NEXT.JS                                        │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "nodejs" || has_framework "express" || has_framework "nextjs"; then
        echo "### Node.js / Express / Next.js Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        # Hardcoded secrets
        HARDCODED_SECRETS=$(grep -rnEi \
            '(api_key|apikey|secret|password|token|auth)\s*[:=]\s*["\x27][A-Za-z0-9+/=_-]{16,}' \
            "$SCAN_DIR" --include="*.js" --include="*.ts" --include="*.mjs" \
            2>/dev/null | grep -v "node_modules\|\.next/\|dist/\|build/\|\.env\|\.example" | head -20 || true)

        if [[ -n "$HARDCODED_SECRETS" ]]; then
            finding "critical" "Hardcoded Secrets in JS/TS Source Code" \
                "API keys, passwords, or tokens appear hardcoded in source files." \
                "$HARDCODED_SECRETS" \
                "Move secrets to environment variables. Rotate exposed credentials."
        fi

        if has_framework "express" && [[ -f "$SCAN_DIR/package.json" ]]; then
            if ! grep -q '"helmet"' "$SCAN_DIR/package.json" 2>/dev/null; then
                finding "medium" "Helmet.js Not Installed (Express)" \
                    "The 'helmet' package sets important security HTTP headers." \
                    "" \
                    "Install: \`npm install helmet\` and use: \`app.use(helmet())\`."
            fi
            if ! grep -q '"express-rate-limit"\|"rate-limit"' "$SCAN_DIR/package.json" 2>/dev/null; then
                finding "medium" "No Rate Limiting (Express)" \
                    "No rate-limiting package found." \
                    "" \
                    "Install: \`npm install express-rate-limit\`."
            fi
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ DJANGO                                                             │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "django"; then
        echo "### Django Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        DJANGO_SETTINGS=$(find "$SCAN_DIR" -name "settings.py" -not -path "*/venv/*" -not -path "*/.git/*" 2>/dev/null | head -5)

        for SF in $DJANGO_SETTINGS; do
            [[ ! -f "$SF" ]] && continue

            if grep -qEi "^\s*DEBUG\s*=\s*True" "$SF" 2>/dev/null; then
                finding "critical" "Django DEBUG Mode Enabled" \
                    "DEBUG=True exposes detailed error pages with code and environment variables." \
                    "File: $SF" \
                    "Set DEBUG=False for production."
            fi

            if grep -qEi "SECRET_KEY.*=.*['\"]django-insecure\|SECRET_KEY.*=.*['\"]changeme" "$SF" 2>/dev/null; then
                finding "critical" "Django SECRET_KEY is Insecure" \
                    "Default or weak secret key — session hijacking is trivial." \
                    "" \
                    "Generate a strong random key and store in environment variables."
            fi

            if grep -qEi "ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]" "$SF" 2>/dev/null; then
                finding "high" "Django ALLOWED_HOSTS Wildcard (*)" \
                    "Allows HTTP Host header attacks." \
                    "" \
                    "Set ALLOWED_HOSTS to actual domain(s)."
            fi

            if ! grep -qEi "SECURE_SSL_REDIRECT\s*=\s*True" "$SF" 2>/dev/null; then
                finding "medium" "Django SECURE_SSL_REDIRECT Not Enabled" \
                    "HTTP not redirected to HTTPS." \
                    "" \
                    "Set SECURE_SSL_REDIRECT=True."
            fi
        done
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ FLASK                                                              │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "flask"; then
        echo "### Flask Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        FLASK_DEBUG=$(grep -rnEi 'app\.run\s*\(.*debug\s*=\s*True\|FLASK_DEBUG\s*=\s*1' \
            "$SCAN_DIR" --include="*.py" 2>/dev/null | grep -v "venv/" | head -10 || true)

        if [[ -n "$FLASK_DEBUG" ]]; then
            finding "critical" "Flask Debug Mode Enabled" \
                "Debug mode exposes an interactive debugger allowing arbitrary code execution." \
                "$FLASK_DEBUG" \
                "Never use debug=True in production."
        fi

        FLASK_SECRET=$(grep -rnEi "secret_key\s*=\s*['\"]?(dev|secret|changeme|test)" \
            "$SCAN_DIR" --include="*.py" 2>/dev/null | grep -v "venv/" | head -5 || true)

        if [[ -n "$FLASK_SECRET" ]]; then
            finding "critical" "Flask SECRET_KEY is Insecure" \
                "Weak or default secret key." \
                "$FLASK_SECRET" \
                "Use a strong random key from environment variables."
        fi
    fi

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ RUBY ON RAILS                                                      │
    # └─────────────────────────────────────────────────────────────────────┘
    if has_framework "rails"; then
        echo "### Ruby on Rails Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        if [[ -f "$SCAN_DIR/config/master.key" ]]; then
            MK_PERM=$(stat -c '%a' "$SCAN_DIR/config/master.key" 2>/dev/null || echo "unknown")
            if [[ "$MK_PERM" != "600" && "$MK_PERM" != "400" ]]; then
                finding "critical" "Rails master.key Permissive ($MK_PERM)" \
                    "The master key decrypts all credentials." \
                    "" \
                    "Run \`chmod 600 config/master.key\`."
            fi
        fi

        RAILS_DEV=$(grep -rnEi "consider_all_requests_local\s*=\s*true" \
            "$SCAN_DIR/config" --include="*.rb" 2>/dev/null | grep "production" | head -5 || true)
        if [[ -n "$RAILS_DEV" ]]; then
            finding "high" "Rails Production Shows Full Error Details" \
                "consider_all_requests_local is true in production." \
                "$RAILS_DEV" \
                "Set to false in production.rb."
        fi
    fi

    # No specific framework detected
    if has_framework "generic"; then
        echo "### Generic Website Audit" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "No specific framework detected. Universal security checks have been applied above." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi


}
