# ── Baseline & Diff Scanning ───────────────────────────────────────────────────
#
# Save a cryptographic baseline of a site's files and compare future scans
# against it — detecting new/changed/removed files and new security issues.
#
# Usage:
#   webscan /var/www/html --baseline save          # Save a baseline
#   webscan /var/www/html --baseline compare       # Compare against baseline
#   webscan /var/www/html --baseline list          # List saved baselines
#   webscan /var/www/html --baseline delete <name> # Delete a baseline

BASELINE_MODE=""  # "save" | "compare" | "list" | "delete"
BASELINE_NAME=""  # optional name for the baseline (default: auto-timestamp)
BASELINE_STORE="${REAL_HOME:-$HOME}/.config/webscan/baselines"

# ── Save a baseline ────────────────────────────────────────────────────────────
baseline_save() {
    local target="$SCAN_DIR"
    local name="${BASELINE_NAME:-$(date '+%Y%m%d_%H%M%S')}"
    local baseline_file="${BASELINE_STORE}/${name}.baseline"

    mkdir -p "$BASELINE_STORE"

    log "Building baseline for: ${target}"
    log "Baseline name: ${name}"

    local count=0
    local tmp_baseline
    tmp_baseline=$(mktemp)

    # Write header
    cat > "$tmp_baseline" <<BEOF
# WebSecurityScanner Baseline
# Target: ${target}
# Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
# Hostname: $(hostname 2>/dev/null || echo unknown)
# Name: ${name}
# Format: SHA256  filepath
BEOF

    # Hash all files (skip excluded patterns)
    find "$target" -type f -size -"${MAX_FILE_SIZE}" 2>/dev/null | \
        grep -vE "$EXCLUDE_PATTERN" | \
        sort | \
        while read -r file; do
            local hash
            hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || \
                   md5sum   "$file" 2>/dev/null | cut -d' ' -f1 || \
                   echo "ERR")
            echo "${hash}  ${file}"
            count=$((count + 1))
        done >> "$tmp_baseline"

    mv "$tmp_baseline" "$baseline_file"
    chmod 600 "$baseline_file"

    # Count lines in baseline file (excluding header)
    local file_count
    file_count=$(grep -c '^[a-f0-9]' "$baseline_file" 2>/dev/null || echo 0)

    echo ""
    ok "Baseline saved: ${baseline_file}"
    ok "Files indexed: ${file_count}"
    echo ""
    echo "To compare future scans against this baseline, run:"
    echo "  webscan ${target} --baseline compare"
    echo "  webscan ${target} --baseline compare --baseline-name ${name}  # use a specific baseline"
    echo ""
    exit 0
}

# ── Compare against a baseline ─────────────────────────────────────────────────
baseline_compare() {
    local target="$SCAN_DIR"

    # Find the most recent baseline for this target (or use named one)
    local baseline_file=""
    if [[ -n "$BASELINE_NAME" ]]; then
        baseline_file="${BASELINE_STORE}/${BASELINE_NAME}.baseline"
    else
        # Find most recent baseline that matches this target
        baseline_file=$(grep -rl "^# Target: ${target}$" "$BASELINE_STORE" 2>/dev/null | \
                        sort -r | head -1 || true)
        # Fall back to most recent baseline file
        if [[ -z "$baseline_file" ]]; then
            baseline_file=$(ls -t "${BASELINE_STORE}"/*.baseline 2>/dev/null | head -1 || true)
        fi
    fi

    if [[ -z "$baseline_file" ]] || [[ ! -f "$baseline_file" ]]; then
        err "No baseline found for: ${target}"
        echo ""
        echo "Save a baseline first with:"
        echo "  webscan ${target} --baseline save"
        exit 1
    fi

    local baseline_date
    baseline_date=$(grep '^# Date:' "$baseline_file" | cut -d' ' -f3-)
    local baseline_target
    baseline_target=$(grep '^# Target:' "$baseline_file" | cut -d' ' -f3-)

    log "Comparing against baseline: $(basename "$baseline_file")"
    log "Baseline date: ${baseline_date}"
    log "Baseline target: ${baseline_target}"
    echo ""

    local new_files=() changed_files=() removed_files=()
    local tmp_current
    tmp_current=$(mktemp)

    # Hash current files
    find "$target" -type f -size -"${MAX_FILE_SIZE}" 2>/dev/null | \
        grep -vE "$EXCLUDE_PATTERN" | \
        sort | \
        while read -r file; do
            local hash
            hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || \
                   md5sum   "$file" 2>/dev/null | cut -d' ' -f1 || \
                   echo "ERR")
            echo "${hash}  ${file}"
        done > "$tmp_current"

    # Files in baseline
    local tmp_baseline_paths tmp_current_paths
    tmp_baseline_paths=$(mktemp)
    tmp_current_paths=$(mktemp)

    grep '^[a-f0-9]' "$baseline_file" | awk '{print $2}' | sort > "$tmp_baseline_paths"
    awk '{print $2}' "$tmp_current"   | sort > "$tmp_current_paths"

    # New files (in current but not in baseline)
    while IFS= read -r f; do
        new_files+=("$f")
    done < <(comm -13 "$tmp_baseline_paths" "$tmp_current_paths")

    # Removed files (in baseline but not in current)
    while IFS= read -r f; do
        removed_files+=("$f")
    done < <(comm -23 "$tmp_baseline_paths" "$tmp_current_paths")

    # Changed files (hash differs for files in both)
    while IFS= read -r line; do
        local hash filepath
        hash=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | awk '{print $2}')
        local baseline_hash
        baseline_hash=$(grep "  ${filepath}$" "$baseline_file" | awk '{print $1}')
        if [[ -n "$baseline_hash" ]] && [[ "$hash" != "$baseline_hash" ]]; then
            changed_files+=("$filepath")
        fi
    done < "$tmp_current"

    rm -f "$tmp_current" "$tmp_baseline_paths" "$tmp_current_paths"

    # ── Output diff report ─────────────────────────────────────────────────────
    local diff_file="${REPORT_FILE%.md}_baseline-diff.md"
    cat > "$diff_file" <<DIFFEOF
# 🔍 Baseline Comparison Report

| Field | Value |
|-------|-------|
| **Scan Target** | \`${target}\` |
| **Baseline Date** | ${baseline_date} |
| **Comparison Date** | $(date '+%B %d, %Y at %H:%M:%S %Z') |
| **New Files** | ${#new_files[@]} |
| **Changed Files** | ${#changed_files[@]} |
| **Removed Files** | ${#removed_files[@]} |

---

DIFFEOF

    # New files
    if [[ ${#new_files[@]} -gt 0 ]]; then
        echo "## 🆕 New Files (${#new_files[@]})" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "> Files that did not exist at baseline time. Review for unauthorized additions." >> "$diff_file"
        echo "" >> "$diff_file"
        for f in "${new_files[@]}"; do
            local ext="${f##*.}"
            local flag=""
            [[ "$ext" =~ ^(php|sh|py|pl|rb|jsp|asp|aspx)$ ]] && flag=" ⚠️ **EXECUTABLE**"
            echo "- \`${f}\`${flag}" >> "$diff_file"
        done
        echo "" >> "$diff_file"
    else
        echo "## 🆕 New Files" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "✅ No new files since baseline." >> "$diff_file"
        echo "" >> "$diff_file"
    fi

    # Changed files
    if [[ ${#changed_files[@]} -gt 0 ]]; then
        echo "## ✏️ Changed Files (${#changed_files[@]})" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "> Files whose content has changed since baseline. Review for unauthorized modifications." >> "$diff_file"
        echo "" >> "$diff_file"
        for f in "${changed_files[@]}"; do
            local ext="${f##*.}"
            local flag=""
            [[ "$ext" =~ ^(php|js|sh|py|html|htm)$ ]] && flag=" ⚠️ **REVIEW**"
            echo "- \`${f}\`${flag}" >> "$diff_file"
        done
        echo "" >> "$diff_file"
    else
        echo "## ✏️ Changed Files" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "✅ No changed files since baseline." >> "$diff_file"
        echo "" >> "$diff_file"
    fi

    # Removed files
    if [[ ${#removed_files[@]} -gt 0 ]]; then
        echo "## 🗑️ Removed Files (${#removed_files[@]})" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "> Files present at baseline that are now missing." >> "$diff_file"
        echo "" >> "$diff_file"
        for f in "${removed_files[@]}"; do
            echo "- \`${f}\`" >> "$diff_file"
        done
        echo "" >> "$diff_file"
    else
        echo "## 🗑️ Removed Files" >> "$diff_file"
        echo "" >> "$diff_file"
        echo "✅ No files removed since baseline." >> "$diff_file"
        echo "" >> "$diff_file"
    fi

    echo "" >> "$diff_file"
    echo "*Baseline comparison generated by Universal Web Security Scanner v3.0*" >> "$diff_file"

    # ── Terminal summary ───────────────────────────────────────────────────────
    echo ""
    echo "── Baseline Comparison ──────────────────────────────────────────────"
    [[ ${#new_files[@]} -gt 0 ]]     && warn "  New files     : ${#new_files[@]}"     || ok "  New files     : 0"
    [[ ${#changed_files[@]} -gt 0 ]] && warn "  Changed files : ${#changed_files[@]}" || ok "  Changed files : 0"
    [[ ${#removed_files[@]} -gt 0 ]] && warn "  Removed files : ${#removed_files[@]}" || ok "  Removed files : 0"
    echo "────────────────────────────────────────────────────────────────────"
    echo ""
    log "Diff report saved: ${diff_file}"

    # Highlight suspicious new executables
    local sus_new=()
    for f in "${new_files[@]}"; do
        local ext="${f##*.}"
        [[ "$ext" =~ ^(php|sh|py|pl|rb|jsp|asp|aspx)$ ]] && sus_new+=("$f")
    done
    if [[ ${#sus_new[@]} -gt 0 ]]; then
        echo ""
        err "⚠️  ${#sus_new[@]} new executable file(s) — review immediately:"
        for f in "${sus_new[@]}"; do err "   ${f}"; done
    fi

    echo ""
    exit 0
}

# ── List saved baselines ───────────────────────────────────────────────────────
baseline_list() {
    echo ""
    echo -e "${BOLD}Saved Baselines:${NC} ${BASELINE_STORE}"
    echo ""
    if [[ ! -d "$BASELINE_STORE" ]] || [[ -z "$(ls -A "$BASELINE_STORE" 2>/dev/null)" ]]; then
        log "No baselines saved yet. Run: webscan /path --baseline save"
    else
        printf "%-30s %-25s %-10s %s\n" "Name" "Date" "Files" "Target"
        printf "%-30s %-25s %-10s %s\n" "$(printf '%0.s-' {1..28})" "$(printf '%0.s-' {1..23})" "----------" "------"
        for f in "$BASELINE_STORE"/*.baseline; do
            [[ -f "$f" ]] || continue
            local name date target files
            name=$(basename "$f" .baseline)
            date=$(grep '^# Date:' "$f" | cut -d' ' -f3- || echo "unknown")
            target=$(grep '^# Target:' "$f" | cut -d' ' -f3- || echo "unknown")
            files=$(grep -c '^[a-f0-9]' "$f" 2>/dev/null || echo 0)
            printf "%-30s %-25s %-10s %s\n" "${name:0:28}" "${date:0:23}" "$files" "$target"
        done
    fi
    echo ""
    exit 0
}

# ── Delete a baseline ──────────────────────────────────────────────────────────
baseline_delete() {
    local name="$1"
    local baseline_file="${BASELINE_STORE}/${name}.baseline"
    if [[ ! -f "$baseline_file" ]]; then
        err "Baseline not found: ${name}"
        exit 1
    fi
    rm -f "$baseline_file"
    ok "Deleted baseline: ${name}"
    exit 0
}

# ── Dispatch baseline subcommand ───────────────────────────────────────────────
run_baseline_mode() {
    [[ -z "$BASELINE_MODE" ]] && return 0
    case "$BASELINE_MODE" in
        save)    baseline_save ;;
        compare) baseline_compare ;;
        list)    baseline_list ;;
        delete)  baseline_delete "${BASELINE_NAME:-}" ;;
        *)
            err "Unknown baseline mode: ${BASELINE_MODE}"
            echo "Valid modes: save | compare | list | delete"
            exit 1 ;;
    esac
}
