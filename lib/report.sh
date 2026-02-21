# ── Report Generation ─────────────────────────────────────────────────────────

init_report() {
    SCAN_START_TIME=$(date +%s)
    FW_LIST=$(IFS=', '; echo "${FRAMEWORKS[*]}")

    # Determine scan scope label for the report header
    local scope_label
    case "$SCAN_MODE" in
        files)  scope_label="File-Based Scan (shared-hosting mode)" ;;
        server) scope_label="Server-Level Scan" ;;
        *)      scope_label="Full Scan (all modules)" ;;
    esac

    cat > "$REPORT_FILE" <<EOF
# 🛡️ Website Security Scan Report

| Field | Value |
|-------|-------|
| **Scan Target** | \`$SCAN_DIR\` |
| **Scan Date** | $(date '+%B %d, %Y at %H:%M:%S %Z') |
| **Hostname** | $(hostname 2>/dev/null || echo "N/A") |
| **Detected Framework(s)** | $FW_LIST |
| **Scan Scope** | $scope_label |
| **Scanner** | Universal Web Security Scanner v3.0 |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
EOF

    # Build TOC dynamically — only include enabled sections
    local toc_num=2
    is_module_enabled 1  && echo "${toc_num}. [Malware & Backdoor Detection](#1-malware--backdoor-detection)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 2  && echo "${toc_num}. [Suspicious Files & Code Patterns](#2-suspicious-files--code-patterns)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 3  && echo "${toc_num}. [Obfuscated & Encoded Code](#3-obfuscated--encoded-code)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 4  && echo "${toc_num}. [File Integrity & Anomalies](#4-file-integrity--anomalies)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 5  && echo "${toc_num}. [Framework-Specific Audit](#5-framework-specific-audit)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 6  && echo "${toc_num}. [Dependency & Supply Chain Risks](#6-dependency--supply-chain-risks)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 7  && echo "${toc_num}. [File Permissions Audit](#7-file-permissions-audit)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 8  && echo "${toc_num}. [Server Configuration Issues](#8-server-configuration-issues)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 9  && echo "${toc_num}. [Secrets & Credential Exposure](#9-secrets--credential-exposure)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 10 && echo "${toc_num}. [Network & Access Security](#10-network--access-security)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 11 && echo "${toc_num}. [Recently Modified Files](#11-recently-modified-files)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 12 && echo "${toc_num}. [SSL/TLS Configuration](#12-ssltls-configuration)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 13 && echo "${toc_num}. [Database Security](#13-database-security)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 14 && echo "${toc_num}. [Container Security](#14-container-security)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    is_module_enabled 15 && echo "${toc_num}. [Logging & Monitoring](#15-logging--monitoring)" >> "$REPORT_FILE" && toc_num=$((toc_num+1))
    [[ "$SHOW_RECOMMENDATIONS" == true ]] && echo "${toc_num}. [Recommendations](#recommendations)" >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

run_parallel_scans() {
    REAL_REPORT_FILE="$REPORT_FILE"

    # Count how many modules are active so we can tune parallelism
    local _active=0
    for _n in $(seq 1 15); do is_module_enabled "$_n" && _active=$((_active+1)); done

    # For smaller scan sets (files-only mode = 9 sections, server-only = 6)
    # we can safely raise parallelism since there are fewer competing jobs.
    local _effective_parallel=$MAX_PARALLEL
    if [[ $_active -le 6 ]]; then
        _effective_parallel=$(( MAX_PARALLEL < 6 ? 6 : MAX_PARALLEL ))
    elif [[ $_active -le 9 ]]; then
        _effective_parallel=$(( MAX_PARALLEL < 5 ? 5 : MAX_PARALLEL ))
    fi

    log "Running $_active scan module(s) with up to $_effective_parallel in parallel..."

    # Launch enabled sections with controlled parallelism
    _running_jobs=0
    for _sec_num in $(seq 1 15); do
        if ! is_module_enabled "$_sec_num"; then
            log "  [skip] Section $_sec_num (disabled)"
            continue
        fi
        _sec_file="$TEMP_DIR/section_$(printf '%02d' $_sec_num).md"
        "scan_section_${_sec_num}" "$_sec_file" &
        _running_jobs=$((_running_jobs + 1))
        if [[ $_running_jobs -ge $_effective_parallel ]]; then
            wait -n 2>/dev/null || wait
            _running_jobs=$((_running_jobs - 1))
        fi
    done
    wait

    # Assemble final report in order (only files that were actually written)
    for _sec_num in $(seq 1 15); do
        _sec_file="$TEMP_DIR/section_$(printf '%02d' $_sec_num).md"
        if [[ -s "$_sec_file" ]]; then
            cat "$_sec_file" >> "$REAL_REPORT_FILE"
        fi
    done

    REPORT_FILE="$REAL_REPORT_FILE"

    # Aggregate issue counts from file-based log
    aggregate_counts
}

generate_summary() {
    log "Generating executive summary..."

    # Calculate security score and grade
    SCORE_DATA=$(calculate_security_score)
    SECURITY_SCORE=$(echo "$SCORE_DATA" | cut -d: -f1)
    SECURITY_GRADE=$(echo "$SCORE_DATA" | cut -d: -f2)
    GRADE_EMOJI=$(echo "$SCORE_DATA" | cut -d: -f3)
    GRADE_DESC=$(get_grade_description "$SECURITY_GRADE")

    if [[ "$CRITICAL" -gt 0 ]]; then
        RISK_LEVEL="🔴 CRITICAL"
        RISK_DESC="Critical security issues require immediate action. The website may already be compromised."
    elif [[ "$HIGH" -gt 0 ]]; then
        RISK_LEVEL="🟠 HIGH"
        RISK_DESC="Significant security weaknesses should be addressed urgently."
    elif [[ "$MEDIUM" -gt 0 ]]; then
        RISK_LEVEL="🟡 MEDIUM"
        RISK_DESC="Moderate security issues should be addressed in the near term."
    elif [[ "$LOW" -gt 0 ]]; then
        RISK_LEVEL="🔵 LOW"
        RISK_DESC="Minor improvements recommended but no serious threats detected."
    else
        RISK_LEVEL="🟢 CLEAN"
        RISK_DESC="No significant issues detected. Continue monitoring and keep everything updated."
    fi

    # Build visual score bar
    local filled=$((SECURITY_SCORE / 5))
    local empty=$((20 - filled))
    local bar=""
    local j
    for ((j=0; j<filled; j++)); do bar+="█"; done
    for ((j=0; j<empty; j++)); do bar+="░"; done

    SUMMARY=$(cat <<EOF

## Executive Summary

### Security Grade: $GRADE_EMOJI **$SECURITY_GRADE** (Score: $SECURITY_SCORE/100)

\`$bar\` $SECURITY_SCORE%

$GRADE_DESC

### Overall Risk Level: $RISK_LEVEL

$RISK_DESC

| Severity | Count | Impact |
|----------|-------|--------|
| 🔴 Critical | $CRITICAL | -10 pts (first), -7 (second), -5 (each after, max -35) |
| 🟠 High | $HIGH | -6 pts (first), -4 (second), -3 (each after, max -25) |
| 🟡 Medium | $MEDIUM | -3 pts each (max -15) |
| 🔵 Low | $LOW | -1 pt each (max -8) |
| ℹ️ Info | $INFO | 0 pts |
| **Total Issues** | **$TOTAL_ISSUES** | |

**Frameworks Detected:** $FW_LIST

---

### Scoring Methodology

| Grade | Score Range | Description |
|-------|-------------|-------------|
| **A+** | 95-100 | Outstanding - Exemplary security posture |
| **A / A-** | 85-94 | Excellent - Strong security posture |
| **B+/B/B-** | 70-84 | Good - Minor improvements needed |
| **C+/C/C-** | 55-69 | Fair - Notable vulnerabilities present |
| **D+/D/D-** | 40-54 | Poor - Significant risks require attention |
| **F** | 30-39 | Critical - Multiple severe vulnerabilities |

*Deductions use diminishing returns: repeated issues of the same severity have reduced impact.*
*Medium and Low severity deductions are capped to prevent score collapse from minor issues alone.*

EOF
)

    TEMP_REPORT=$(mktemp)
    awk -v summary="$SUMMARY" 'BEGIN { found=0 } /^---$/ && found==0 { print; print ""; print summary; found=1; next } {print}' \
        "$REPORT_FILE" > "$TEMP_REPORT"
    mv "$TEMP_REPORT" "$REPORT_FILE"
}

write_recommendations() {
    if [[ "$SHOW_RECOMMENDATIONS" == true ]]; then
cat >> "$REPORT_FILE" <<'EOF'
---

## Recommendations

### Immediate Actions (if critical issues found)

1. **Quarantine infected files** — Move malicious files outside the web root
2. **Reset all credentials** — Admin passwords, database passwords, API keys, SSH keys
3. **Replace framework core files** — Download fresh copies matching your version
4. **Audit the database** — Check for injected content and unauthorized users
5. **Check crontab** — Run `crontab -l` and inspect for unauthorized entries
6. **Scan other sites** — If on shared hosting, check other sites on the same account

### Universal Hardening Checklist

- [ ] Update all frameworks, libraries, and dependencies to latest versions
- [ ] Remove unused plugins, themes, packages, and dead code
- [ ] Set proper file permissions (dirs: 755, files: 644, configs: 640)
- [ ] Block script execution in upload/media directories
- [ ] Use strong passwords and enable 2FA for all admin accounts
- [ ] Move sensitive files outside web root (.env, backups, SQL dumps)
- [ ] Install a Web Application Firewall (WAF)
- [ ] Set up automated backups (files + database)
- [ ] Enforce HTTPS site-wide
- [ ] Configure security headers (CSP, HSTS, X-Frame-Options)
- [ ] Implement rate limiting on login and API endpoints
- [ ] Disable directory listing
- [ ] Block .git, .env, and sensitive files via server config
- [ ] Use environment variables for all secrets
- [ ] Schedule regular security scans (weekly minimum)

### Security Headers

```apache
# Apache (.htaccess)
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

```nginx
# Nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### Framework Security Guides

| Framework | Guide |
|-----------|-------|
| WordPress | [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/) |
| Laravel | [Laravel Security Docs](https://laravel.com/docs/security) |
| Django | [Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/) |
| Express.js | [Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html) |
| Drupal | [Security in Drupal](https://www.drupal.org/docs/security-in-drupal) |
| Rails | [Security Guide](https://guides.rubyonrails.org/security.html) |
| Flask | [Security Considerations](https://flask.palletsprojects.com/en/latest/security/) |

---

EOF
    fi

    cat >> "$REPORT_FILE" <<EOF
*Report generated by Universal Web Security Scanner v3.0 on $(date '+%B %d, %Y at %H:%M:%S %Z')*
*Automated scan — manual review of flagged items is recommended.*
*For critical findings, consider engaging a professional security auditor.*
EOF
}

final_output() {
    # Calculate scan duration
    SCAN_END_TIME=$(date +%s)
    SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))
    DURATION_MIN=$((SCAN_DURATION / 60))
    DURATION_SEC=$((SCAN_DURATION % 60))

    # Build terminal score bar with color
    local filled=$((SECURITY_SCORE / 5))
    local empty=$((20 - filled))
    local bar_color=""
    if [[ $SECURITY_SCORE -ge 80 ]]; then bar_color="$GREEN"
    elif [[ $SECURITY_SCORE -ge 60 ]]; then bar_color="$YELLOW"
    else bar_color="$RED"
    fi
    local bar_filled="" bar_empty=""
    local j
    for ((j=0; j<filled; j++)); do bar_filled+="█"; done
    for ((j=0; j<empty; j++)); do bar_empty+="░"; done

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                       SCAN COMPLETE                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    log "Security Grade : $GRADE_EMOJI $SECURITY_GRADE (Score: $SECURITY_SCORE/100)"
    echo -e "                 ${bar_color}${bar_filled}${NC}${bar_empty} ${SECURITY_SCORE}%"
    log "Frameworks     : $FW_LIST"
    log "Risk Level     : $RISK_LEVEL"
    log "Total Issues   : $TOTAL_ISSUES"
    [[ "$CRITICAL" -gt 0 ]] && err "  Critical : $CRITICAL"
    [[ "$HIGH" -gt 0 ]]     && warn "  High     : $HIGH"
    [[ "$MEDIUM" -gt 0 ]]   && warn "  Medium   : $MEDIUM"
    [[ "$LOW" -gt 0 ]]      && ok "  Low      : $LOW"
    [[ "$INFO" -gt 0 ]]     && ok "  Info     : $INFO"
    echo ""
    log "Scan Duration  : ${DURATION_MIN}m ${DURATION_SEC}s"
    log "Files Scanned  : $(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)"
    log "Report saved to: $REPORT_FILE"
    echo ""
}
