# ── JSON & SARIF Output Formats ───────────────────────────────────────────────

generate_json_report() {
    local json_file="${REPORT_FILE%.md}.json"
    log "Generating JSON report..."

    local scan_date hostname_val duration_val files_scanned
    scan_date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    hostname_val=$(hostname 2>/dev/null || echo "unknown")
    duration_val=$((${SCAN_END_TIME:-$(date +%s)} - ${SCAN_START_TIME:-$(date +%s)}))
    files_scanned=$(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)

    if command -v python3 &>/dev/null; then
        python3 - "$REPORT_FILE" "$json_file" <<PYEOF
import json, sys, re, os

report_path = sys.argv[1]
out_path    = sys.argv[2]

# Read raw markdown for findings extraction
with open(report_path, encoding='utf-8', errors='replace') as f:
    content = f.read()

sev_map = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'INFO': 'info'}

def extract_findings(md):
    findings = []
    pattern = re.compile(
        r'####\s+.*?\*\*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\*\s*[—-]\s*(.+?)\n'
        r'(.*?)(?=####|\Z)',
        re.DOTALL
    )
    for m in pattern.finditer(md):
        sev   = m.group(1)
        title = m.group(2).strip()
        body  = m.group(3).strip()

        det_m = re.search(r'```\n(.*?)```', body, re.DOTALL)
        rec_m = re.search(r'\*\*Recommendation:\*\*\s*(.*)', body)
        desc  = re.sub(r'<details>.*?</details>', '', body, flags=re.DOTALL)
        desc  = re.sub(r'> \*\*Recommendation:.*', '', desc).strip()

        findings.append({
            'severity':       sev_map.get(sev, 'info'),
            'title':          title,
            'description':    desc,
            'details':        det_m.group(1).strip() if det_m else None,
            'recommendation': rec_m.group(1).strip() if rec_m else None,
        })
    return findings

# Section-to-name map
section_names = {
    '01': 'Malware & Backdoor Detection',
    '02': 'Suspicious Files & Code Patterns',
    '03': 'Obfuscated & Encoded Code',
    '04': 'File Integrity & Anomalies',
    '05': 'Framework-Specific Audit',
    '06': 'Dependency & Supply Chain Risks',
    '07': 'File Permissions Audit',
    '08': 'Server Configuration Issues',
    '09': 'Secrets & Credential Exposure',
    '10': 'Network & Access Security',
    '11': 'Recently Modified Files',
    '12': 'SSL/TLS Configuration',
    '13': 'Database Security',
    '14': 'Container Security',
    '15': 'Logging & Monitoring',
}

payload = {
    'schema_version': '1.0',
    'scanner':        'Universal Web Security Scanner v3.0',
    'scan': {
        'target':       os.environ.get('SCAN_DIR', ''),
        'date':         os.environ.get('SCAN_DATE', ''),
        'hostname':     os.environ.get('HOSTNAME_VAL', ''),
        'mode':         os.environ.get('SCAN_MODE', 'all'),
        'frameworks':   os.environ.get('FW_LIST', '').split(', '),
        'duration_sec': int(os.environ.get('DURATION_VAL', '0')),
        'files_scanned':int(os.environ.get('FILES_SCANNED', '0')),
    },
    'summary': {
        'security_score': int(os.environ.get('SECURITY_SCORE', '0')),
        'security_grade': os.environ.get('SECURITY_GRADE', ''),
        'risk_level':     os.environ.get('CLEAN_RISK', ''),
        'total_issues':   int(os.environ.get('TOTAL_ISSUES', '0')),
        'critical':       int(os.environ.get('CRITICAL', '0')),
        'high':           int(os.environ.get('HIGH', '0')),
        'medium':         int(os.environ.get('MEDIUM', '0')),
        'low':            int(os.environ.get('LOW', '0')),
        'info':           int(os.environ.get('INFO', '0')),
    },
    'findings': extract_findings(content),
}

with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)

print(f"JSON report: {out_path}")
PYEOF
    else
        # Minimal fallback without Python
        cat > "$json_file" <<JSONEOF
{
  "schema_version": "1.0",
  "scanner": "Universal Web Security Scanner v3.0",
  "scan": {
    "target": "$(echo "$SCAN_DIR" | sed 's/"/\\"/g')",
    "date": "${scan_date}",
    "hostname": "${hostname_val}",
    "mode": "${SCAN_MODE}",
    "duration_sec": ${duration_val},
    "files_scanned": ${files_scanned}
  },
  "summary": {
    "security_score": ${SECURITY_SCORE},
    "security_grade": "${SECURITY_GRADE}",
    "risk_level": "$(echo "$RISK_LEVEL" | sed 's/^[^ ]* //' | sed 's/"/\\"/g')",
    "total_issues": ${TOTAL_ISSUES},
    "critical": ${CRITICAL},
    "high": ${HIGH},
    "medium": ${MEDIUM},
    "low": ${LOW},
    "info": ${INFO}
  },
  "findings": []
}
JSONEOF
    fi

    ok "JSON report saved to: ${json_file}"
    JSON_REPORT_FILE="$json_file"
}

generate_sarif_report() {
    local sarif_file="${REPORT_FILE%.md}.sarif"
    log "Generating SARIF report..."

    if command -v python3 &>/dev/null; then
        python3 - "$REPORT_FILE" "$sarif_file" <<'PYEOF'
import json, sys, re, os, hashlib

report_path = sys.argv[1]
out_path    = sys.argv[2]

with open(report_path, encoding='utf-8', errors='replace') as f:
    content = f.read()

# SARIF severity levels
sev_sarif = {
    'CRITICAL': 'error',
    'HIGH':     'error',
    'MEDIUM':   'warning',
    'LOW':      'note',
    'INFO':     'none',
}

rules  = []
results = []
seen_rules = {}

pattern = re.compile(
    r'####\s+.*?\*\*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\*\s*[—-]\s*(.+?)\n'
    r'(.*?)(?=####|\Z)',
    re.DOTALL
)

for i, m in enumerate(pattern.finditer(content)):
    sev   = m.group(1)
    title = m.group(2).strip()
    body  = m.group(3).strip()

    rec_m = re.search(r'\*\*Recommendation:\*\*\s*(.*)', body)
    desc  = re.sub(r'<details>.*?</details>', '', body, flags=re.DOTALL)
    desc  = re.sub(r'> \*\*Recommendation:.*', '', desc).strip()

    rule_id = 'WSS-' + hashlib.md5(title.encode()).hexdigest()[:6].upper()

    if rule_id not in seen_rules:
        seen_rules[rule_id] = True
        rules.append({
            'id': rule_id,
            'name': re.sub(r'[^A-Za-z0-9]', '', title)[:64],
            'shortDescription': {'text': title},
            'fullDescription':  {'text': desc[:1000] if desc else title},
            'helpUri': 'https://owasp.org/www-project-top-ten/',
            'properties': {
                'tags': ['security', sev.lower()],
                'severity': sev.lower(),
            },
            'defaultConfiguration': {
                'level': sev_sarif.get(sev, 'note')
            },
        })

    recommendation = rec_m.group(1).strip() if rec_m else ''

    results.append({
        'ruleId':  rule_id,
        'level':   sev_sarif.get(sev, 'note'),
        'message': {
            'text': (desc[:500] if desc else title)
                    + ('\n\nRecommendation: ' + recommendation if recommendation else '')
        },
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {
                    'uri': os.environ.get('SCAN_DIR', '.').lstrip('/'),
                    'uriBaseId': '%SRCROOT%'
                }
            }
        }],
        'properties': {'severity': sev.lower()},
    })

sarif = {
    'version': '2.1.0',
    '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
    'runs': [{
        'tool': {
            'driver': {
                'name':            'WebSecurityScanner',
                'version':         '3.0',
                'fullName':        'Universal Web Security Scanner v3.0',
                'informationUri':  'https://github.com/codesandideas/website-security-script',
                'rules':           rules,
            }
        },
        'results':  results,
        'artifacts': [{
            'location': {
                'uri': os.environ.get('SCAN_DIR', '.').lstrip('/'),
                'uriBaseId': '%SRCROOT%'
            }
        }],
        'invocations': [{
            'executionSuccessful': True,
            'commandLine': f"webscan {os.environ.get('SCAN_DIR', '.')}",
        }],
    }]
}

with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print(f"SARIF report: {out_path}")
PYEOF
    else
        warn "Python 3 required for SARIF output — skipping SARIF generation"
        return 0
    fi

    ok "SARIF report saved to: ${sarif_file}"
    SARIF_REPORT_FILE="$sarif_file"
}

# ── Export env vars used by Python output generators ──────────────────────────
export_report_env() {
    export SCAN_DIR SCAN_MODE FW_LIST SECURITY_SCORE SECURITY_GRADE SCAN_START_TIME
    export CRITICAL HIGH MEDIUM LOW INFO TOTAL_ISSUES RISK_LEVEL
    export HOSTNAME_VAL="$(hostname 2>/dev/null || echo unknown)"
    export SCAN_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    export DURATION_VAL="${SCAN_DURATION:-0}"
    export FILES_SCANNED="$(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)"
    export CLEAN_RISK="$(echo "$RISK_LEVEL" | sed 's/^[^ ]* //')"
}
