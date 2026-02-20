# ── WordPress Allowlist & False Positive Filtering ─────────────────────────────
USE_ALLOWLIST=true

# Known-safe WordPress core paths — fallback when checksums unavailable (grep -E compatible)
WP_CORE_EXCLUDE_PATHS='wp-admin/upload\.php|wp-admin/includes/|wp-admin/js/|wp-admin/css/|wp-admin/images/|wp-includes/js/|wp-includes/css/|wp-includes/images/|wp-includes/fonts/|wp-includes/blocks/|wp-includes/ID3/|wp-includes/SimplePie/|wp-includes/Requests/'

# Check if WordPress allowlisting is active
is_wp_allowlist_active() {
    [[ "$USE_ALLOWLIST" == true ]] && has_framework "wordpress"
}

# Check if a file path is within wp-admin/ or wp-includes/ (core directories)
is_wp_core_path() {
    local path="$1"
    [[ "$path" == *"/wp-admin/"* || "$path" == *"/wp-includes/"* ]]
}

# Filter out WordPress files verified by official checksums (pipe function)
# Falls back to path-based filtering if integrity data is unavailable
filter_wp_verified() {
    if ! is_wp_allowlist_active; then
        cat
        return
    fi

    local verified_file="$TEMP_DIR/wp_verified.txt"

    # If checksum-based verification ran successfully, use it
    if [[ "${WP_INTEGRITY_AVAILABLE:-false}" == true && -s "$verified_file" ]]; then
        # Build grep pattern from verified file list
        # Escape dots and slashes for grep, join with |
        local pattern
        pattern=$(sed 's/[.[\*^$()+?{|]/\\&/g' "$verified_file" | paste -sd'|' -)
        if [[ -n "$pattern" ]]; then
            grep -vE "$pattern"
        else
            cat
        fi
    else
        # Fallback: path-based filtering (offline/no checksums)
        grep -vE "$WP_CORE_EXCLUDE_PATHS"
    fi
}

# Load and apply user-defined .scanignore patterns
filter_allowlist() {
    local scanignore=""

    # Check scan directory first, then config directory
    if [[ -f "$SCAN_DIR/.scanignore" ]]; then
        scanignore="$SCAN_DIR/.scanignore"
    elif [[ -f "$CONFIG_DIR/allowlist" ]]; then
        scanignore="$CONFIG_DIR/allowlist"
    fi

    if [[ -z "$scanignore" ]]; then
        cat
        return
    fi

    # Build grep pattern from .scanignore (skip comments and empty lines)
    local patterns=()
    while IFS= read -r line; do
        line="${line%%#*}"        # strip inline comments
        line="$(echo "$line" | xargs)" # trim whitespace
        [[ -z "$line" ]] && continue
        # Convert glob-style * to regex .*
        line="${line//\*/.*}"
        patterns+=("$line")
    done < "$scanignore"

    if [[ ${#patterns[@]} -eq 0 ]]; then
        cat
        return
    fi

    local ignore_regex
    ignore_regex=$(IFS='|'; echo "${patterns[*]}")
    grep -vE "$ignore_regex"
}

# Combined filter: applies all active filters to scan results
filter_results() {
    if [[ "$USE_ALLOWLIST" != true ]]; then
        cat
        return
    fi
    filter_wp_verified | filter_allowlist
}
