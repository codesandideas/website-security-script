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

    # Lenient scoring: gentle deductions with aggressive diminishing returns
    # No issue combination should feel punishing — the goal is actionable feedback
    local crit_penalty=0 high_penalty=0 med_penalty=0 low_penalty=0

    # Critical: -10 first, -7 second, -5 each after (cap at 35)
    local i
    for ((i=1; i<=CRITICAL; i++)); do
        if [[ $i -eq 1 ]]; then crit_penalty=$((crit_penalty + 10))
        elif [[ $i -eq 2 ]]; then crit_penalty=$((crit_penalty + 7))
        else crit_penalty=$((crit_penalty + 5))
        fi
    done
    [[ $crit_penalty -gt 35 ]] && crit_penalty=35

    # High: -6 first, -4 second, -3 each after (cap at 25)
    for ((i=1; i<=HIGH; i++)); do
        if [[ $i -eq 1 ]]; then high_penalty=$((high_penalty + 6))
        elif [[ $i -eq 2 ]]; then high_penalty=$((high_penalty + 4))
        else high_penalty=$((high_penalty + 3))
        fi
    done
    [[ $high_penalty -gt 25 ]] && high_penalty=25

    # Medium: -3 each (cap at 15 total)
    med_penalty=$((MEDIUM * 3))
    [[ $med_penalty -gt 15 ]] && med_penalty=15

    # Low: -1 each (cap at 8 total)
    low_penalty=$((LOW * 1))
    [[ $low_penalty -gt 8 ]] && low_penalty=8

    score=$((score - crit_penalty - high_penalty - med_penalty - low_penalty))

    # Floor: score never drops below 30 — every site has something to build on
    [[ $score -lt 30 ]] && score=30

    # Ensure score stays in 30-100 range
    [[ $score -gt 100 ]] && score=100

    # Grade: generous boundaries — focus on encouragement
    if [[ $score -ge 95 ]]; then
        grade="A+"; grade_emoji="🟢"
    elif [[ $score -ge 90 ]]; then
        grade="A"; grade_emoji="🟢"
    elif [[ $score -ge 85 ]]; then
        grade="A-"; grade_emoji="🟢"
    elif [[ $score -ge 80 ]]; then
        grade="B+"; grade_emoji="🟡"
    elif [[ $score -ge 75 ]]; then
        grade="B"; grade_emoji="🟡"
    elif [[ $score -ge 70 ]]; then
        grade="B-"; grade_emoji="🟡"
    elif [[ $score -ge 65 ]]; then
        grade="C+"; grade_emoji="🟠"
    elif [[ $score -ge 60 ]]; then
        grade="C"; grade_emoji="🟠"
    elif [[ $score -ge 55 ]]; then
        grade="C-"; grade_emoji="🟠"
    elif [[ $score -ge 50 ]]; then
        grade="D+"; grade_emoji="🔴"
    elif [[ $score -ge 45 ]]; then
        grade="D"; grade_emoji="🔴"
    elif [[ $score -ge 40 ]]; then
        grade="D-"; grade_emoji="🔴"
    else
        grade="F"; grade_emoji="💀"
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
        F)       echo "Multiple critical vulnerabilities detected. Immediate remediation required." ;;
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

# ── Module Gating ─────────────────────────────────────────────────────────────
# Returns 0 (true) when a section is enabled, 1 (false) when disabled.
# Uses bash indirect expansion so no subshell is spawned.
is_module_enabled() {
    local sec_num="$1"
    local var_name
    case "$sec_num" in
        1)  var_name="SCAN_01_MALWARE" ;;
        2)  var_name="SCAN_02_SUSPICIOUS" ;;
        3)  var_name="SCAN_03_OBFUSCATION" ;;
        4)  var_name="SCAN_04_INTEGRITY" ;;
        5)  var_name="SCAN_05_FRAMEWORK" ;;
        6)  var_name="SCAN_06_DEPENDENCIES" ;;
        7)  var_name="SCAN_07_PERMISSIONS" ;;
        8)  var_name="SCAN_08_SERVER_CONFIG" ;;
        9)  var_name="SCAN_09_SECRETS" ;;
        10) var_name="SCAN_10_NETWORK" ;;
        11) var_name="SCAN_11_MODIFIED_FILES" ;;
        12) var_name="SCAN_12_SSL" ;;
        13) var_name="SCAN_13_DATABASE" ;;
        14) var_name="SCAN_14_CONTAINER" ;;
        15) var_name="SCAN_15_LOGGING" ;;
        *)  return 0 ;;  # Unknown section — enable by default
    esac
    [[ "${!var_name}" != false ]]
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
