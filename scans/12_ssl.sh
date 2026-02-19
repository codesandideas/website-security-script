scan_section_12() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 12: SSL/TLS CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════════════
    log "Checking SSL/TLS configuration..."

    cat >> "$REPORT_FILE" <<'EOF'
---

## 12. SSL/TLS Configuration

Checking SSL certificates, TLS protocol versions, cipher suites, and HTTPS enforcement.

EOF

    # Collect server config files for SSL checks
    SSL_CONFIG_FILES=""
    for cfg in /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*; do
        [[ -f "$cfg" ]] 2>/dev/null && SSL_CONFIG_FILES="$SSL_CONFIG_FILES $cfg"
    done

    # ── 12a. Expired/Invalid Certificate ──────────────────────────────────────────
    if command -v openssl &>/dev/null; then
        # Try to extract hostname from server config
        SSL_HOSTNAME=""
        if [[ -n "$SSL_CONFIG_FILES" ]]; then
            SSL_HOSTNAME=$(grep -hEo 'server_name\s+[^;]+' $SSL_CONFIG_FILES 2>/dev/null | head -1 | awk '{print $2}' || true)
            if [[ -z "$SSL_HOSTNAME" ]]; then
                SSL_HOSTNAME=$(grep -hEo 'ServerName\s+\S+' $SSL_CONFIG_FILES 2>/dev/null | head -1 | awk '{print $2}' || true)
            fi
        fi

        if [[ -n "$SSL_HOSTNAME" && "$SSL_HOSTNAME" != "localhost" && "$SSL_HOSTNAME" != "_" ]]; then
            CERT_INFO=$(echo | $TIMEOUT_CMD openssl s_client -connect "$SSL_HOSTNAME:443" -servername "$SSL_HOSTNAME" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
            if [[ -n "$CERT_INFO" ]]; then
                CERT_EXPIRY=$(echo "$CERT_INFO" | grep 'notAfter=' | cut -d= -f2)
                if [[ -n "$CERT_EXPIRY" ]]; then
                    EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || true)
                    NOW_EPOCH=$(date +%s)
                    if [[ -n "$EXPIRY_EPOCH" && "$EXPIRY_EPOCH" -lt "$NOW_EPOCH" ]]; then
                        finding "critical" "SSL Certificate Expired" \
                            "The SSL certificate for $SSL_HOSTNAME has expired." \
                            "Expiry date: $CERT_EXPIRY" \
                            "Renew the SSL certificate immediately using Let's Encrypt or your certificate provider."
                    elif [[ -n "$EXPIRY_EPOCH" ]]; then
                        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                        if [[ "$DAYS_LEFT" -lt 30 ]]; then
                            finding "high" "SSL Certificate Expiring Soon" \
                                "The SSL certificate for $SSL_HOSTNAME expires in $DAYS_LEFT days." \
                                "Expiry date: $CERT_EXPIRY" \
                                "Renew the SSL certificate before it expires."
                        else
                            echo "✅ SSL certificate for $SSL_HOSTNAME is valid ($DAYS_LEFT days remaining)." >> "$REPORT_FILE"
                            echo "" >> "$REPORT_FILE"
                        fi
                    fi
                fi
            else
                echo "⚠️ Could not connect to $SSL_HOSTNAME:443 to check certificate." >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        else
            echo "ℹ️ No server hostname detected in config — skipping certificate expiry check." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    else
        echo "ℹ️ openssl not installed — skipping certificate checks." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 12b. HTTP to HTTPS Redirect ───────────────────────────────────────────────
    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        REDIRECT_FOUND=false
        if grep -qEi 'return\s+301\s+https://|rewrite\s+\^.*https://.*permanent|RewriteRule.*https://%\{' $SSL_CONFIG_FILES 2>/dev/null; then
            REDIRECT_FOUND=true
        fi

        if [[ "$REDIRECT_FOUND" != true ]]; then
            finding "high" "Missing HTTP to HTTPS Redirect" \
                "No HTTP to HTTPS redirect rule found in server configuration." \
                "Checked: $SSL_CONFIG_FILES" \
                "Add a redirect from HTTP (port 80) to HTTPS (port 443) in your server configuration."
        else
            echo "✅ HTTP to HTTPS redirect is configured." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    else
        echo "ℹ️ No server configuration files found — skipping HTTPS redirect check." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # ── 12c. Weak TLS Protocols ───────────────────────────────────────────────────
    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        WEAK_TLS=$(grep -hEin 'TLSv1[^.]|TLSv1\.0|TLSv1\.1|SSLv2|SSLv3|SSLProtocol.*all' $SSL_CONFIG_FILES 2>/dev/null | grep -iv 'TLSv1\.[23]' || true)
        if [[ -n "$WEAK_TLS" ]]; then
            finding "high" "Weak TLS Protocols Enabled" \
                "Server configuration allows deprecated TLS protocols (TLSv1.0, TLSv1.1, SSLv2, or SSLv3)." \
                "$WEAK_TLS" \
                "Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3."
        else
            echo "✅ No weak TLS protocols detected in configuration." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    fi

    # ── 12d. Weak Cipher Suites ───────────────────────────────────────────────────
    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        WEAK_CIPHERS=$(grep -hEin 'RC4|DES|MD5|EXPORT|NULL|aNULL|eNULL' $SSL_CONFIG_FILES 2>/dev/null | grep -i 'ssl_ciphers\|SSLCipherSuite' || true)
        if [[ -n "$WEAK_CIPHERS" ]]; then
            finding "medium" "Weak Cipher Suites Configured" \
                "Server configuration includes weak or insecure cipher suites (RC4, DES, MD5, EXPORT, NULL)." \
                "$WEAK_CIPHERS" \
                "Remove weak ciphers and use only modern, secure cipher suites."
        else
            echo "✅ No weak cipher suites detected in configuration." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    fi

    # ── 12e. Missing HSTS Header ─────────────────────────────────────────────────
    if [[ -n "$SSL_CONFIG_FILES" ]]; then
        HSTS_FOUND=$(grep -hEi 'Strict-Transport-Security|add_header.*HSTS' $SSL_CONFIG_FILES 2>/dev/null || true)
        if [[ -z "$HSTS_FOUND" ]]; then
            finding "medium" "Missing HSTS Header" \
                "HTTP Strict Transport Security (HSTS) is not configured in server settings." \
                "Checked: $SSL_CONFIG_FILES" \
                "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        else
            echo "✅ HSTS header is configured." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    fi


}
