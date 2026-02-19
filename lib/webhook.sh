# ── Webhook Delivery ──────────────────────────────────────────────────────────
send_webhook() {
    [[ -z "$WEBHOOK_URL" ]] && return 0

    log "Sending report to webhook..."

    # Clean risk level and grade (remove emoji)
    CLEAN_RISK=$(echo "$RISK_LEVEL" | sed 's/^[^ ]* //')
    CLEAN_GRADE=$(echo "$SECURITY_GRADE" | sed 's/[^A-F]*//g')

    # Read report content and escape for JSON
    REPORT_CONTENT=$(cat "$REPORT_FILE")

    # Build JSON payload using python for safe escaping (available on most servers)
    # Falls back to basic sed escaping if python is not available
    if command -v python3 &>/dev/null; then
        JSON_PAYLOAD=$(python3 -c "
import json, sys
data = {
    'api_key': sys.argv[1],
    'email': sys.argv[2],
    'hostname': sys.argv[3],
    'scan_target': sys.argv[4],
    'frameworks': sys.argv[5],
    'risk_level': sys.argv[6],
    'security_grade': sys.argv[7],
    'security_score': int(sys.argv[8]),
    'total_issues': int(sys.argv[9]),
    'critical': int(sys.argv[10]),
    'high': int(sys.argv[11]),
    'medium': int(sys.argv[12]),
    'low': int(sys.argv[13]),
    'info': int(sys.argv[14]),
    'report': sys.stdin.read()
}
print(json.dumps(data))
" "$API_KEY" "$NOTIFY_EMAIL" "$(hostname 2>/dev/null || echo unknown)" "$SCAN_DIR" \
  "$FW_LIST" "$CLEAN_RISK" "$SECURITY_GRADE" "$SECURITY_SCORE" \
  "$TOTAL_ISSUES" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$INFO" \
  < "$REPORT_FILE")
    elif command -v python &>/dev/null; then
        JSON_PAYLOAD=$(python -c "
import json, sys
data = {
    'api_key': sys.argv[1],
    'email': sys.argv[2],
    'hostname': sys.argv[3],
    'scan_target': sys.argv[4],
    'frameworks': sys.argv[5],
    'risk_level': sys.argv[6],
    'security_grade': sys.argv[7],
    'security_score': int(sys.argv[8]),
    'total_issues': int(sys.argv[9]),
    'critical': int(sys.argv[10]),
    'high': int(sys.argv[11]),
    'medium': int(sys.argv[12]),
    'low': int(sys.argv[13]),
    'info': int(sys.argv[14]),
    'report': sys.stdin.read()
}
print(json.dumps(data))
" "$API_KEY" "$NOTIFY_EMAIL" "$(hostname 2>/dev/null || echo unknown)" "$SCAN_DIR" \
  "$FW_LIST" "$CLEAN_RISK" "$SECURITY_GRADE" "$SECURITY_SCORE" \
  "$TOTAL_ISSUES" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$INFO" \
  < "$REPORT_FILE")
    else
        # Fallback: basic JSON escaping with sed
        ESCAPED_REPORT=$(cat "$REPORT_FILE" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | \
            awk '{printf "%s\\n", $0}')
        JSON_PAYLOAD=$(cat <<JSONEOF
{
  "api_key": "$API_KEY",
  "email": "$NOTIFY_EMAIL",
  "hostname": "$(hostname 2>/dev/null || echo unknown)",
  "scan_target": "$SCAN_DIR",
  "frameworks": "$FW_LIST",
  "risk_level": "$CLEAN_RISK",
  "security_grade": "$SECURITY_GRADE",
  "security_score": $SECURITY_SCORE,
  "total_issues": $TOTAL_ISSUES,
  "critical": $CRITICAL,
  "high": $HIGH,
  "medium": $MEDIUM,
  "low": $LOW,
  "info": $INFO,
  "report": "$ESCAPED_REPORT"
}
JSONEOF
)
    fi

    # Send via curl
    HTTP_RESPONSE=$(curl -s -o "$TEMP_DIR/webhook_response.txt" -w "%{http_code}" \
        -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD" \
        --max-time 30 \
        2>/dev/null || echo "000")

    if [[ "$HTTP_RESPONSE" == "200" ]]; then
        ok "Report sent successfully to webhook"
        RESPONSE_MSG=$(cat "$TEMP_DIR/webhook_response.txt" 2>/dev/null || echo "")
        [[ -n "$RESPONSE_MSG" ]] && log "Server response: $RESPONSE_MSG"
    else
        err "Webhook delivery failed (HTTP $HTTP_RESPONSE)"
        [[ -f "$TEMP_DIR/webhook_response.txt" ]] && err "Response: $(cat "$TEMP_DIR/webhook_response.txt")"
        warn "Report is still saved locally: $REPORT_FILE"
    fi
}
