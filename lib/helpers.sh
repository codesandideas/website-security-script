# ── Detected frameworks (populated by detection phase) ───────────────────────
declare -a FRAMEWORKS=()

# ── Cleanup ──────────────────────────────────────────────────────────────────
INTERRUPTED=false
cleanup() {
    [[ -f "$FILE_LIST" ]] && rm -f "$FILE_LIST"
    rm -rf "$TEMP_DIR"
    if [[ "$INTERRUPTED" == true ]]; then
        err "Scan interrupted by user"
        exit 130
    fi
}
trap 'INTERRUPTED=true; cleanup' INT TERM
trap cleanup EXIT

# ── File List Cache ───────────────────────────────────────────────────────────
build_file_list() {
    log "Building file index..."
    FILE_LIST="$TEMP_DIR/all_files.txt"
    find "$SCAN_DIR" -type f -size -"$MAX_FILE_SIZE" 2>/dev/null | \
        grep -vE "$EXCLUDE_PATTERN" > "$FILE_LIST" || true
    local count=$(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)
    log "Indexed $count files for scanning"
}

# ── Security Score Calculation ────────────────────────────────────────────────
calculate_security_score() {
    local score=100
    local grade=""
    local grade_emoji=""

    # Point deductions
    score=$((score - CRITICAL * 25))
    score=$((score - HIGH * 15))
    score=$((score - MEDIUM * 5))
    score=$((score - LOW * 2))

    # Ensure score doesn't go below 0
    [[ $score -lt 0 ]] && score=0

    # Calculate grade
    if [[ $score -ge 90 ]]; then
        grade="A"; grade_emoji="🟢"
    elif [[ $score -ge 80 ]]; then
        grade="B"; grade_emoji="🟡"
    elif [[ $score -ge 70 ]]; then
        grade="C"; grade_emoji="🟠"
    elif [[ $score -ge 60 ]]; then
        grade="D"; grade_emoji="🔴"
    elif [[ $score -ge 50 ]]; then
        grade="E"; grade_emoji="⚫"
    else
        grade="F"; grade_emoji="⚫"
    fi

    echo "$score:$grade:$grade_emoji"
}

get_grade_description() {
    local grade="$1"
    case "$grade" in
        "A") echo "Excellent security posture. Continue regular monitoring and keep systems updated." ;;
        "B") echo "Good security with minor improvements needed. Address medium and low severity issues." ;;
        "C") echo "Fair security with notable vulnerabilities. Address high severity issues promptly." ;;
        "D") echo "Poor security with significant risks. Multiple high and critical issues require attention." ;;
        "E") echo "Critical security state. Severe vulnerabilities present. Immediate action required." ;;
        "F") echo "Failed security state. Critical compromise likely. Emergency security response needed." ;;
    esac
}

# ── Helper Functions ──────────────────────────────────────────────────────────
exclude_noise() { grep -vE "$EXCLUDE_PATTERN"; }

get_file_size() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        stat -f%z "$1" 2>/dev/null || echo 0
    else
        stat -c%s "$1" 2>/dev/null || echo 0
    fi
}

safe_grep() {
    local pattern="$1"
    shift
    $TIMEOUT_CMD grep -rnEi "$pattern" "$@" 2>/dev/null | exclude_noise | head -100 || true
}

safe_find() {
    local dir="$1"
    shift
    if [[ -f "$FILE_LIST" ]]; then
        # Use cached file list and filter by pattern
        cat "$FILE_LIST" | while read -r file; do
            [[ -f "$file" ]] && "$@" "$file" 2>/dev/null
        done | exclude_noise | head -100 || true
    else
        $TIMEOUT_CMD find "$dir" "$@" 2>/dev/null | exclude_noise | head -100 || true
    fi
}

# ── Logging ──────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }

# ── Issue Counting ───────────────────────────────────────────────────────────
COUNTS_LOG="$TEMP_DIR/counts.log"
touch "$COUNTS_LOG"

increment_issue() {
    local severity="$1"
    (
        flock -x 200
        echo "$severity" >> "$COUNTS_LOG"
    ) 200>"$COUNTS_LOG.lock"
}

aggregate_counts() {
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; TOTAL_ISSUES=0
    if [[ -s "$COUNTS_LOG" ]]; then
        while IFS= read -r sev; do
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            case "$sev" in
                critical) CRITICAL=$((CRITICAL + 1)) ;;
                high)     HIGH=$((HIGH + 1)) ;;
                medium)   MEDIUM=$((MEDIUM + 1)) ;;
                low)      LOW=$((LOW + 1)) ;;
                info)     INFO=$((INFO + 1)) ;;
            esac
        done < "$COUNTS_LOG"
    fi
}

severity_badge() {
    case "$1" in
        critical) echo "🔴 **CRITICAL**" ;;
        high)     echo "🟠 **HIGH**" ;;
        medium)   echo "🟡 **MEDIUM**" ;;
        low)      echo "🔵 **LOW**" ;;
        info)     echo "ℹ️ **INFO**" ;;
    esac
}

finding() {
    local severity="$1" title="$2" description="$3"
    local details="${4:-}" recommendation="${5:-}"

    increment_issue "$severity"

    cat >> "$REPORT_FILE" <<EOF

#### $(severity_badge "$severity") — $title

$description

EOF

    if [[ -n "$details" ]]; then
        cat >> "$REPORT_FILE" <<EOF
<details>
<summary>Details (click to expand)</summary>

\`\`\`
$details
\`\`\`

</details>

EOF
    fi

    if [[ -n "$recommendation" ]]; then
        cat >> "$REPORT_FILE" <<EOF
> **Recommendation:** $recommendation

EOF
    fi
}

has_framework() {
    local fw="$1"
    for f in "${FRAMEWORKS[@]}"; do
        [[ "$f" == "$fw" ]] && return 0
    done
    return 1
}

check_timeout() {
    local current_time=$(date +%s)
    local elapsed=$((current_time - SCAN_START_TIME))
    if [[ $elapsed -gt $SCAN_TIMEOUT ]]; then
        err "Scan timeout reached ($SCAN_TIMEOUT seconds)"
        return 1
    fi
    return 0
}
