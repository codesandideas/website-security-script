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

    # Weighted point deductions with diminishing returns for repeated issues
    # First few issues of each severity have full impact, then taper off
    local crit_penalty=0 high_penalty=0 med_penalty=0 low_penalty=0

    # Critical: -25 for first, -20 for second, -15 each after (min 10 each)
    local i
    for ((i=1; i<=CRITICAL; i++)); do
        if [[ $i -eq 1 ]]; then crit_penalty=$((crit_penalty + 25))
        elif [[ $i -eq 2 ]]; then crit_penalty=$((crit_penalty + 20))
        else crit_penalty=$((crit_penalty + 15))
        fi
    done

    # High: -15 for first, -12 for second, -10 each after
    for ((i=1; i<=HIGH; i++)); do
        if [[ $i -eq 1 ]]; then high_penalty=$((high_penalty + 15))
        elif [[ $i -eq 2 ]]; then high_penalty=$((high_penalty + 12))
        else high_penalty=$((high_penalty + 10))
        fi
    done

    # Medium: -5 each (cap at 30 total)
    med_penalty=$((MEDIUM * 5))
    [[ $med_penalty -gt 30 ]] && med_penalty=30

    # Low: -2 each (cap at 15 total)
    low_penalty=$((LOW * 2))
    [[ $low_penalty -gt 15 ]] && low_penalty=15

    score=$((score - crit_penalty - high_penalty - med_penalty - low_penalty))

    # Ensure score stays in 0-100 range
    [[ $score -lt 0 ]] && score=0
    [[ $score -gt 100 ]] && score=100

    # Grade: A+ for perfect, then standard A-F with +/- modifiers
    if [[ $score -ge 97 ]]; then
        grade="A+"; grade_emoji="🟢"
    elif [[ $score -ge 93 ]]; then
        grade="A"; grade_emoji="🟢"
    elif [[ $score -ge 90 ]]; then
        grade="A-"; grade_emoji="🟢"
    elif [[ $score -ge 87 ]]; then
        grade="B+"; grade_emoji="🟡"
    elif [[ $score -ge 83 ]]; then
        grade="B"; grade_emoji="🟡"
    elif [[ $score -ge 80 ]]; then
        grade="B-"; grade_emoji="🟡"
    elif [[ $score -ge 77 ]]; then
        grade="C+"; grade_emoji="🟠"
    elif [[ $score -ge 73 ]]; then
        grade="C"; grade_emoji="🟠"
    elif [[ $score -ge 70 ]]; then
        grade="C-"; grade_emoji="🟠"
    elif [[ $score -ge 65 ]]; then
        grade="D+"; grade_emoji="🔴"
    elif [[ $score -ge 60 ]]; then
        grade="D"; grade_emoji="🔴"
    elif [[ $score -ge 50 ]]; then
        grade="D-"; grade_emoji="🔴"
    elif [[ $score -ge 35 ]]; then
        grade="F"; grade_emoji="💀"
    else
        grade="F-"; grade_emoji="☠️"
    fi

    echo "$score:$grade:$grade_emoji"
}

get_grade_description() {
    local grade="$1"
    case "$grade" in
        A+|A|A-) echo "Excellent security posture. Continue regular monitoring and keep systems updated." ;;
        B+|B|B-) echo "Good security with minor improvements needed. Address medium and low severity issues." ;;
        C+|C|C-) echo "Fair security with notable vulnerabilities. Address high severity issues promptly." ;;
        D+|D)    echo "Poor security with significant risks. Multiple high and critical issues require attention." ;;
        D-)      echo "Critical security state. Severe vulnerabilities present. Immediate action required." ;;
        F)       echo "Failed security assessment. Critical compromise likely. Emergency response needed." ;;
        F-)      echo "Severely compromised. Multiple critical vulnerabilities detected. Assume breach and respond immediately." ;;
        *)       echo "Unable to determine security posture." ;;
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
    case "$severity" in
        critical|high|medium|low|info) ;;
        *) err "Invalid severity: $severity"; return 1 ;;
    esac
    (
        flock -x 200
        echo "$severity" >> "$COUNTS_LOG"
    ) 200>"$COUNTS_LOG.lock"
}

aggregate_counts() {
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; TOTAL_ISSUES=0
    if [[ -s "$COUNTS_LOG" ]]; then
        (
            flock -s 200
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
            # Export counts to temp file since subshell can't set parent vars
            echo "$CRITICAL $HIGH $MEDIUM $LOW $INFO $TOTAL_ISSUES" > "$COUNTS_LOG.agg"
        ) 200>"$COUNTS_LOG.lock"
        if [[ -f "$COUNTS_LOG.agg" ]]; then
            read CRITICAL HIGH MEDIUM LOW INFO TOTAL_ISSUES < "$COUNTS_LOG.agg"
        fi
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
