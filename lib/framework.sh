# ── Framework & Language Detection ────────────────────────────────────────────
detect_frameworks() {
    log "Detecting frameworks and CMS..."

    # WordPress
    [[ -f "$SCAN_DIR/wp-config.php" || -f "$SCAN_DIR/wp-login.php" ]] && FRAMEWORKS+=("wordpress")

    # Laravel
    [[ -f "$SCAN_DIR/artisan" && -d "$SCAN_DIR/app" && -d "$SCAN_DIR/bootstrap" ]] && FRAMEWORKS+=("laravel")

    # Drupal
    [[ -f "$SCAN_DIR/core/lib/Drupal.php" || -f "$SCAN_DIR/sites/default/settings.php" ]] && FRAMEWORKS+=("drupal")

    # Joomla
    [[ -f "$SCAN_DIR/configuration.php" && -d "$SCAN_DIR/administrator" ]] && FRAMEWORKS+=("joomla")

    # Magento
    [[ -f "$SCAN_DIR/bin/magento" || -f "$SCAN_DIR/app/etc/env.php" ]] && FRAMEWORKS+=("magento")

    # CodeIgniter
    [[ -d "$SCAN_DIR/application" && -d "$SCAN_DIR/system" && -f "$SCAN_DIR/index.php" ]] && FRAMEWORKS+=("codeigniter")

    # Symfony
    [[ -f "$SCAN_DIR/symfony.lock" || -f "$SCAN_DIR/config/bundles.php" ]] && FRAMEWORKS+=("symfony")

    # CakePHP
    [[ -f "$SCAN_DIR/config/app.php" && -d "$SCAN_DIR/src/Controller" ]] && FRAMEWORKS+=("cakephp")

    # Node.js / Express / Next.js
    if [[ -f "$SCAN_DIR/package.json" ]]; then
        FRAMEWORKS+=("nodejs")
        grep -q '"next"' "$SCAN_DIR/package.json" 2>/dev/null && FRAMEWORKS+=("nextjs")
        grep -q '"express"' "$SCAN_DIR/package.json" 2>/dev/null && FRAMEWORKS+=("express")
    fi

    # Django
    [[ -f "$SCAN_DIR/manage.py" ]] && grep -q "django" "$SCAN_DIR/manage.py" 2>/dev/null && FRAMEWORKS+=("django")

    # Flask
    grep -rql "from flask import\|from flask_" "$SCAN_DIR"/*.py 2>/dev/null && FRAMEWORKS+=("flask")

    # Ruby on Rails
    [[ -f "$SCAN_DIR/Gemfile" ]] && grep -q "rails" "$SCAN_DIR/Gemfile" 2>/dev/null && FRAMEWORKS+=("rails")

    # Static site / generic
    [[ ${#FRAMEWORKS[@]} -eq 0 ]] && FRAMEWORKS+=("generic")

    # Remove duplicates
    FRAMEWORKS=($(printf '%s\n' "${FRAMEWORKS[@]}" | sort -u))

    for fw in "${FRAMEWORKS[@]}"; do
        ok "Detected: $fw"
    done
    echo ""

    # Determine primary language
    HAS_PHP=false; HAS_JS=false; HAS_PYTHON=false; HAS_RUBY=false
    find "$SCAN_DIR" -maxdepth 3 -name "*.php" -type f 2>/dev/null | head -1 | grep -q . && HAS_PHP=true
    find "$SCAN_DIR" -maxdepth 3 -name "*.js" -type f 2>/dev/null | head -1 | grep -q . && HAS_JS=true
    find "$SCAN_DIR" -maxdepth 3 -name "*.py" -type f 2>/dev/null | head -1 | grep -q . && HAS_PYTHON=true
    find "$SCAN_DIR" -maxdepth 3 -name "*.rb" -type f 2>/dev/null | head -1 | grep -q . && HAS_RUBY=true

    # Build file list cache for faster scanning
    build_file_list
}
