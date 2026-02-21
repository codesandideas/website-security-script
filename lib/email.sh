# ── SMTP Email Delivery ────────────────────────────────────────────────────────
#
# Uses curl's SMTP support — no mailx/sendmail/postfix required.
# Configure with:
#   webscan --set-smtp-host smtp.gmail.com:587
#   webscan --set-smtp-user you@gmail.com
#   webscan --set-smtp-pass "your-app-password"
#   webscan --set-smtp-from "Scanner <you@gmail.com>"
#   webscan --test-email recipient@example.com
#
# For Gmail App Passwords: https://myaccount.google.com/apppasswords
# For SMTP relay services: SendGrid, Mailgun, Postmark, Amazon SES

SMTP_HOST="${SMTP_HOST:-}"
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
SMTP_FROM="${SMTP_FROM:-}"

send_email() {
    [[ -z "$NOTIFY_EMAIL" ]] && return 0
    [[ -z "$SMTP_HOST" ]]    && { warn "SMTP not configured. Run: webscan --set-smtp-host <host:port>"; return 0; }
    [[ -z "$SMTP_USER" ]]    && { warn "SMTP user not set. Run: webscan --set-smtp-user <email>"; return 0; }

    log "Sending email report to ${NOTIFY_EMAIL}..."

    local from_addr="${SMTP_FROM:-$SMTP_USER}"
    local subject="[Security Scanner] ${SECURITY_GRADE} — ${SCAN_DIR} (${RISK_LEVEL//[^A-Z]/})"
    local boundary="boundary_webscan_$(date +%s)"

    # Build HTML email body (embeds score/summary, attaches full HTML report if it exists)
    local grade_color
    if [[ "$SECURITY_SCORE" -ge 80 ]]; then grade_color="#22c55e"
    elif [[ "$SECURITY_SCORE" -ge 60 ]]; then grade_color="#f59e0b"
    else grade_color="#ef4444"
    fi

    local email_body_file="$TEMP_DIR/email_body.txt"

    cat > "$email_body_file" <<EMAILEOF
From: ${from_addr}
To: ${NOTIFY_EMAIL}
Subject: ${subject}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;margin:0;padding:0}
.wrap{max-width:580px;margin:24px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#1e293b,#0f172a);color:#f8fafc;padding:28px 32px}
.header h1{font-size:20px;margin:0 0 4px}
.header p{font-size:13px;color:#94a3b8;margin:0}
.score-section{padding:28px 32px;text-align:center;border-bottom:1px solid #f1f5f9}
.grade{font-size:56px;font-weight:900;color:${grade_color};line-height:1}
.grade-label{font-size:14px;color:#64748b;margin-top:4px}
.score-num{font-size:22px;font-weight:700;color:${grade_color}}
.stats{display:flex;justify-content:center;gap:0;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin:16px 32px}
.stat{flex:1;padding:14px 8px;text-align:center;border-right:1px solid #e2e8f0}
.stat:last-child{border-right:none}
.stat-num{font-size:22px;font-weight:800}
.stat-label{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px}
.crit{color:#dc2626}.high{color:#ea580c}.med{color:#d97706}.low{color:#2563eb}.info-c{color:#6b7280}
.meta{padding:16px 32px;background:#f8fafc;font-size:13px;color:#475569}
.meta table{width:100%;border-collapse:collapse}
.meta td{padding:5px 0;vertical-align:top}
.meta td:first-child{color:#94a3b8;width:120px}
.footer{padding:20px 32px;font-size:12px;color:#94a3b8;text-align:center;border-top:1px solid #f1f5f9}
</style></head>
<body>
<div class="wrap">
  <div class="header">
    <h1>🛡️ Website Security Scan Report</h1>
    <p>Universal Web Security Scanner v3.0</p>
  </div>
  <div class="score-section">
    <div class="grade">${SECURITY_GRADE}</div>
    <div class="grade-label"><span class="score-num">${SECURITY_SCORE}/100</span> — ${RISK_LEVEL}</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-num crit">${CRITICAL}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num high">${HIGH}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num med">${MEDIUM}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-num low">${LOW}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-num info-c">${INFO}</div><div class="stat-label">Info</div></div>
  </div>
  <div class="meta">
    <table>
      <tr><td>Target</td><td><code>${SCAN_DIR}</code></td></tr>
      <tr><td>Scanned</td><td>$(date '+%B %d, %Y at %H:%M %Z')</td></tr>
      <tr><td>Hostname</td><td>$(hostname 2>/dev/null || echo "N/A")</td></tr>
      <tr><td>Frameworks</td><td>${FW_LIST}</td></tr>
      <tr><td>Duration</td><td>${DURATION_MIN}m ${DURATION_SEC}s</td></tr>
    </table>
  </div>
  <div class="footer">
    Full report attached · Universal Web Security Scanner v3.0<br>
    Automated scan — manual review of flagged items is recommended.
  </div>
</div>
</body></html>

EMAILEOF

    # Attach the markdown report
    if [[ -f "$REPORT_FILE" ]]; then
        printf -- '--%s\n' "$boundary"                                   >> "$email_body_file"
        printf 'Content-Type: text/markdown; charset=UTF-8\n'            >> "$email_body_file"
        printf 'Content-Disposition: attachment; filename="%s"\n\n' \
            "$(basename "$REPORT_FILE")"                                  >> "$email_body_file"
        cat "$REPORT_FILE"                                                >> "$email_body_file"
        printf '\n'                                                       >> "$email_body_file"
    fi

    printf -- '--%s--\n' "$boundary" >> "$email_body_file"

    # Send via curl SMTP
    local smtp_url="smtp://${SMTP_HOST}"
    # Use STARTTLS for port 587, SSL for port 465
    local tls_flag=""
    if echo "$SMTP_HOST" | grep -q ':465'; then
        smtp_url="smtps://${SMTP_HOST}"
    else
        tls_flag="--ssl-reqd"
    fi

    local curl_opts=(
        --silent
        --show-error
        --url "$smtp_url"
        --mail-from "$SMTP_USER"
        --mail-rcpt "$NOTIFY_EMAIL"
        --upload-file "$email_body_file"
        --max-time 30
    )
    [[ -n "$SMTP_USER" ]] && curl_opts+=(--user "${SMTP_USER}:${SMTP_PASS}")
    [[ -n "$tls_flag" ]]  && curl_opts+=("$tls_flag")

    local smtp_err
    smtp_err=$(curl "${curl_opts[@]}" 2>&1)

    if [[ $? -eq 0 ]]; then
        ok "Email sent successfully to ${NOTIFY_EMAIL}"
    else
        err "Email delivery failed: ${smtp_err}"
        warn "Check SMTP config with: webscan --show-config"
        warn "Test connection with:   webscan --test-email ${NOTIFY_EMAIL}"
    fi
}

# Send a test email to verify SMTP settings
send_test_email() {
    local recipient="$1"
    [[ -z "$SMTP_HOST" ]] && { err "SMTP host not configured. Run: webscan --set-smtp-host smtp.example.com:587"; exit 1; }

    log "Sending test email to ${recipient}..."

    # Use temp values for test
    NOTIFY_EMAIL="$recipient"
    SECURITY_GRADE="A+"
    SECURITY_SCORE=100
    RISK_LEVEL="🟢 CLEAN"
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0
    FW_LIST="Test"
    SCAN_DIR="/test"
    DURATION_MIN=0; DURATION_SEC=1
    REPORT_FILE="$TEMP_DIR/test_report.md"
    echo "# Test Report" > "$REPORT_FILE"

    send_email
    exit 0
}
