# ── Report Generation ─────────────────────────────────────────────────────────

init_report() {
    SCAN_START_TIME=$(date +%s)
    FW_LIST=$(IFS=', '; echo "${FRAMEWORKS[*]}")

    cat > "$REPORT_FILE" <<EOF
# 🛡️ Website Security Scan Report

| Field | Value |
|-------|-------|
| **Scan Target** | \`$SCAN_DIR\` |
| **Scan Date** | $(date '+%B %d, %Y at %H:%M:%S %Z') |
| **Hostname** | $(hostname 2>/dev/null || echo "N/A") |
| **Detected Framework(s)** | $FW_LIST |
| **Scanner** | Universal Web Security Scanner v3.0 |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Malware & Backdoor Detection](#1-malware--backdoor-detection)
3. [Suspicious Files & Code Patterns](#2-suspicious-files--code-patterns)
4. [Obfuscated & Encoded Code](#3-obfuscated--encoded-code)
5. [File Integrity & Anomalies](#4-file-integrity--anomalies)
6. [Framework-Specific Audit](#5-framework-specific-audit)
7. [Dependency & Supply Chain Risks](#6-dependency--supply-chain-risks)
8. [File Permissions Audit](#7-file-permissions-audit)
9. [Server Configuration Issues](#8-server-configuration-issues)
10. [Secrets & Credential Exposure](#9-secrets--credential-exposure)
11. [Network & Access Security](#10-network--access-security)
12. [Recently Modified Files](#11-recently-modified-files)
13. [SSL/TLS Configuration](#12-ssltls-configuration)
14. [Database Security](#13-database-security)
15. [Container Security](#14-container-security)
16. [Logging & Monitoring](#15-logging--monitoring)
17. [Recommendations](#recommendations)

---

EOF

    # Remove recommendations TOC entry if hidden
    if [[ "$SHOW_RECOMMENDATIONS" != true ]]; then
        sed -i '/\[Recommendations\](#recommendations)/d' "$REPORT_FILE"
    fi
}

run_parallel_scans() {
    REAL_REPORT_FILE="$REPORT_FILE"

    # Launch sections with limited parallelism
    _running_jobs=0
    for _sec_num in $(seq 1 15); do
        _sec_file="$TEMP_DIR/section_$(printf '%02d' $_sec_num).md"
        "scan_section_${_sec_num}" "$_sec_file" &
        _running_jobs=$((_running_jobs + 1))
        if [[ $_running_jobs -ge $MAX_PARALLEL ]]; then
            wait -n 2>/dev/null || wait
            _running_jobs=$((_running_jobs - 1))
        fi
    done
    wait

    # Assemble final report in order
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
| 🔴 Critical | $CRITICAL | -25 pts (first), -20 (second), -15 (each after) |
| 🟠 High | $HIGH | -15 pts (first), -12 (second), -10 (each after) |
| 🟡 Medium | $MEDIUM | -5 pts each (max -30) |
| 🔵 Low | $LOW | -2 pts each (max -15) |
| ℹ️ Info | $INFO | 0 pts |
| **Total Issues** | **$TOTAL_ISSUES** | |

**Frameworks Detected:** $FW_LIST

---

### Scoring Methodology

| Grade | Score Range | Description |
|-------|-------------|-------------|
| **A+** | 97-100 | Outstanding - Exemplary security posture |
| **A / A-** | 90-96 | Excellent - Strong security posture |
| **B+/B/B-** | 80-89 | Good - Minor improvements needed |
| **C+/C/C-** | 70-79 | Fair - Notable vulnerabilities present |
| **D+/D** | 60-69 | Poor - Significant risks require attention |
| **D-** | 50-59 | Critical - Severe vulnerabilities |
| **F** | 35-49 | Failed - Critical compromise likely |
| **F-** | 0-34 | Severely compromised - Assume breach |

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
