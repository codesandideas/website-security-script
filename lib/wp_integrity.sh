# ── WordPress Integrity Verification via Official Checksums ───────────────────

# Cross-platform md5 wrapper
_wp_md5() {
    local file="$1"
    if command -v md5sum &>/dev/null; then
        md5sum "$file" | cut -d' ' -f1
    elif command -v md5 &>/dev/null; then
        md5 -q "$file"
    else
        return 1
    fi
}

# Read WordPress version from wp-includes/version.php
wp_get_version() {
    local ver_file="$SCAN_DIR/wp-includes/version.php"
    [[ -f "$ver_file" ]] || return 1
    grep '^\$wp_version\s*=' "$ver_file" 2>/dev/null | sed "s/.*'\(.*\)'.*/\1/"
}

# Fetch official checksums from WordPress API, output as "md5  filepath" lines
wp_fetch_checksums() {
    local version="$1"
    local json_file="$TEMP_DIR/wp_checksums.json"
    local checksums_file="$TEMP_DIR/wp_checksums.txt"

    # Download checksums JSON
    if ! curl -sS --max-time 15 \
        "https://api.wordpress.org/core/checksums/1.0/?version=${version}&locale=en_US" \
        -o "$json_file" 2>/dev/null; then
        return 1
    fi

    # Verify we got valid data (not an error response)
    if ! grep -q '"checksums"' "$json_file" 2>/dev/null; then
        return 1
    fi

    # Parse JSON to "md5  filepath" format
    if command -v python3 &>/dev/null; then
        python3 -c "
import json, sys
with open('$json_file') as f:
    d = json.load(f)
checksums = d.get('checksums', {})
if not checksums:
    sys.exit(1)
for path, md5 in checksums.items():
    print(f'{md5}  {path}')
" > "$checksums_file" 2>/dev/null
    else
        # Fallback: basic grep/sed parsing
        grep -oP '"[^"]+"\s*:\s*"[a-f0-9]{32}"' "$json_file" | \
            sed 's/"\([^"]*\)"\s*:\s*"\([a-f0-9]*\)"/\2  \1/' | \
            grep -v '"checksums"' > "$checksums_file" 2>/dev/null
    fi

    [[ -s "$checksums_file" ]] && return 0 || return 1
}

# Verify WordPress core files against official checksums
wp_verify_core() {
    local checksums_file="$TEMP_DIR/wp_checksums.txt"
    local verified_file="$TEMP_DIR/wp_verified.txt"
    local modified_file="$TEMP_DIR/wp_modified.txt"
    local extra_file="$TEMP_DIR/wp_extra.txt"

    # Initialize output files
    : > "$verified_file"
    : > "$modified_file"
    : > "$extra_file"

    [[ -s "$checksums_file" ]] || return 1

    # Build associative array of official checksums
    declare -A official_checksums
    while IFS= read -r line; do
        local md5="${line%%  *}"
        local filepath="${line#*  }"
        official_checksums["$filepath"]="$md5"
    done < "$checksums_file"

    # Check each official file
    local verified=0 modified=0
    for filepath in "${!official_checksums[@]}"; do
        local full_path="$SCAN_DIR/$filepath"
        if [[ -f "$full_path" ]]; then
            local local_md5
            local_md5=$(_wp_md5 "$full_path") || continue
            if [[ "$local_md5" == "${official_checksums[$filepath]}" ]]; then
                echo "$filepath" >> "$verified_file"
                verified=$((verified + 1))
            else
                echo "$filepath" >> "$modified_file"
                modified=$((modified + 1))
            fi
        fi
    done

    # Find extra files in wp-admin/ and wp-includes/ not in official checksums
    while IFS= read -r full_path; do
        local rel_path="${full_path#$SCAN_DIR/}"
        if [[ -z "${official_checksums[$rel_path]+x}" ]]; then
            echo "$rel_path" >> "$extra_file"
        fi
    done < <(find "$SCAN_DIR/wp-admin" "$SCAN_DIR/wp-includes" -type f 2>/dev/null | \
        grep -vE '\.git/|node_modules/' || true)

    log "WP Core Integrity: $verified verified, $modified modified, $(wc -l < "$extra_file" 2>/dev/null || echo 0) extra"
    return 0
}

# Read version from a plugin's main PHP file header
wp_get_plugin_version() {
    local plugin_dir="$1"
    local version=""
    for pf in "$plugin_dir"/*.php; do
        [[ -f "$pf" ]] || continue
        version=$(grep -i "Version:" "$pf" 2>/dev/null | head -1 | sed 's/.*Version:\s*//i' | tr -d '[:space:]')
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    done
    return 1
}

# Read version from a theme's style.css header
wp_get_theme_version() {
    local theme_dir="$1"
    local style="$theme_dir/style.css"
    [[ -f "$style" ]] || return 1
    local version
    version=$(grep -i "Version:" "$style" 2>/dev/null | head -1 | sed 's/.*Version:\s*//i' | tr -d '[:space:]')
    [[ -n "$version" ]] && echo "$version" || return 1
}

# Verify a plugin against official wordpress.org release
wp_verify_plugin() {
    local plugin_dir="$1"
    local slug
    slug=$(basename "$plugin_dir")
    local version
    version=$(wp_get_plugin_version "$plugin_dir") || return 1

    local zip_url="https://downloads.wordpress.org/plugin/${slug}.${version}.zip"
    local zip_file="$TEMP_DIR/wp_plugin_${slug}.zip"
    local extract_dir="$TEMP_DIR/wp_plugin_${slug}"

    # Download official zip
    if ! curl -sS --max-time 30 -o "$zip_file" "$zip_url" 2>/dev/null; then
        return 1
    fi

    # Check it's actually a zip (not a 404 HTML page)
    if ! file "$zip_file" 2>/dev/null | grep -qi 'zip'; then
        rm -f "$zip_file"
        return 1
    fi

    mkdir -p "$extract_dir"
    if ! unzip -qo "$zip_file" -d "$extract_dir" 2>/dev/null; then
        rm -f "$zip_file"
        return 1
    fi
    rm -f "$zip_file"

    local official_dir="$extract_dir/$slug"
    [[ -d "$official_dir" ]] || return 1

    local verified_file="$TEMP_DIR/wp_verified.txt"
    local modified_file="$TEMP_DIR/wp_modified.txt"

    # Compare each file in the official release
    while IFS= read -r official_file; do
        local rel="${official_file#$official_dir/}"
        local local_file="$plugin_dir/$rel"
        local wp_rel="wp-content/plugins/$slug/$rel"

        if [[ -f "$local_file" ]]; then
            local off_md5 loc_md5
            off_md5=$(_wp_md5 "$official_file") || continue
            loc_md5=$(_wp_md5 "$local_file") || continue
            if [[ "$off_md5" == "$loc_md5" ]]; then
                echo "$wp_rel" >> "$verified_file"
            else
                echo "$wp_rel" >> "$modified_file"
            fi
        fi
    done < <(find "$official_dir" -type f 2>/dev/null)

    rm -rf "$extract_dir"
    return 0
}

# Verify a theme against official wordpress.org release
wp_verify_theme() {
    local theme_dir="$1"
    local slug
    slug=$(basename "$theme_dir")
    local version
    version=$(wp_get_theme_version "$theme_dir") || return 1

    local zip_url="https://downloads.wordpress.org/theme/${slug}.${version}.zip"
    local zip_file="$TEMP_DIR/wp_theme_${slug}.zip"
    local extract_dir="$TEMP_DIR/wp_theme_${slug}"

    if ! curl -sS --max-time 30 -o "$zip_file" "$zip_url" 2>/dev/null; then
        return 1
    fi

    if ! file "$zip_file" 2>/dev/null | grep -qi 'zip'; then
        rm -f "$zip_file"
        return 1
    fi

    mkdir -p "$extract_dir"
    if ! unzip -qo "$zip_file" -d "$extract_dir" 2>/dev/null; then
        rm -f "$zip_file"
        return 1
    fi
    rm -f "$zip_file"

    local official_dir="$extract_dir/$slug"
    [[ -d "$official_dir" ]] || return 1

    local verified_file="$TEMP_DIR/wp_verified.txt"
    local modified_file="$TEMP_DIR/wp_modified.txt"

    while IFS= read -r official_file; do
        local rel="${official_file#$official_dir/}"
        local local_file="$theme_dir/$rel"
        local wp_rel="wp-content/themes/$slug/$rel"

        if [[ -f "$local_file" ]]; then
            local off_md5 loc_md5
            off_md5=$(_wp_md5 "$official_file") || continue
            loc_md5=$(_wp_md5 "$local_file") || continue
            if [[ "$off_md5" == "$loc_md5" ]]; then
                echo "$wp_rel" >> "$verified_file"
            else
                echo "$wp_rel" >> "$modified_file"
            fi
        fi
    done < <(find "$official_dir" -type f 2>/dev/null)

    rm -rf "$extract_dir"
    return 0
}

# Orchestrator: verify core + plugins + themes
wp_run_integrity_check() {
    has_framework "wordpress" || return 0

    local version
    version=$(wp_get_version) || { warn "Could not detect WordPress version"; return 1; }

    log "WordPress $version detected — running integrity check..."

    # Initialize files
    : > "$TEMP_DIR/wp_verified.txt"
    : > "$TEMP_DIR/wp_modified.txt"
    : > "$TEMP_DIR/wp_extra.txt"

    # Core verification (fast — single API call)
    if wp_fetch_checksums "$version"; then
        wp_verify_core
        WP_INTEGRITY_AVAILABLE=true
    else
        warn "Could not fetch WordPress checksums (offline?) — using path-based filtering"
        WP_INTEGRITY_AVAILABLE=false
        return 1
    fi

    # Plugin verification
    local plugin_dir="$SCAN_DIR/wp-content/plugins"
    if [[ -d "$plugin_dir" ]]; then
        for pd in "$plugin_dir"/*/; do
            [[ -d "$pd" ]] || continue
            wp_verify_plugin "$pd" 2>/dev/null || true
        done
    fi

    # Theme verification
    local theme_dir="$SCAN_DIR/wp-content/themes"
    if [[ -d "$theme_dir" ]]; then
        for td in "$theme_dir"/*/; do
            [[ -d "$td" ]] || continue
            wp_verify_theme "$td" 2>/dev/null || true
        done
    fi

    local v_count m_count e_count
    v_count=$(wc -l < "$TEMP_DIR/wp_verified.txt" 2>/dev/null || echo 0)
    m_count=$(wc -l < "$TEMP_DIR/wp_modified.txt" 2>/dev/null || echo 0)
    e_count=$(wc -l < "$TEMP_DIR/wp_extra.txt" 2>/dev/null || echo 0)
    ok "WP Integrity: $v_count verified, $m_count modified, $e_count extra files"

    return 0
}

# Global flag for whether integrity data is available
WP_INTEGRITY_AVAILABLE=false
