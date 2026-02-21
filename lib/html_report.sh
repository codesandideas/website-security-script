# ── HTML Report Generation ─────────────────────────────────────────────────────

generate_html_report() {
    local html_file="${REPORT_FILE%.md}.html"
    log "Generating HTML report..."

    # Determine grade colour
    local grade_color
    if [[ "$SECURITY_SCORE" -ge 80 ]]; then grade_color="#22c55e"
    elif [[ "$SECURITY_SCORE" -ge 60 ]]; then grade_color="#f59e0b"
    else grade_color="#ef4444"
    fi

    # Compute SVG semi-circle gauge arc (using awk for float math)
    local gauge_arc
    gauge_arc=$(awk -v s="$SECURITY_SCORE" -v c="$grade_color" 'BEGIN {
        pi = 3.14159265358979
        r = 80; cx = 100; cy = 100
        # Arc from angle pi (left) to angle pi*(1-s/100) (right for s=100)
        end_a = pi * (1 - s / 100)
        ex = cx + r * cos(end_a)
        ey = cy - r * sin(end_a)
        la = (s > 50) ? 1 : 0
        printf "M20,100 A80,80 0 %d,1 %.2f,%.2f", la, ex, ey
    }')

    # Compute SVG donut chart segments
    local total_visible=$(( CRITICAL + HIGH + MEDIUM + LOW + INFO ))
    [[ "$total_visible" -eq 0 ]] && total_visible=1  # avoid division by zero
    local donut_segments
    donut_segments=$(python3 - <<PYEOF 2>/dev/null || awk -v c="$CRITICAL" -v h="$HIGH" -v m="$MEDIUM" -v l="$LOW" -v i="$INFO" -v tv="$total_visible" 'BEGIN {
        # Simple awk fallback: just print a grey circle
        print "<circle cx=\"60\" cy=\"60\" r=\"45\" fill=\"none\" stroke=\"#e5e7eb\" stroke-width=\"20\"/>"
    }' /dev/null
import math, sys
counts  = [int("$CRITICAL"), int("$HIGH"), int("$MEDIUM"), int("$LOW"), int("$INFO")]
colors  = ["#ef4444","#f97316","#f59e0b","#3b82f6","#6b7280"]
total   = sum(counts) or 1
cx, cy, r = 60, 60, 45
offset = -90  # start at top
segs = []
for count, color in zip(counts, colors):
    if count == 0:
        continue
    frac = count / total
    deg  = frac * 360
    start_r = math.radians(offset)
    end_r   = math.radians(offset + deg)
    x1 = cx + r * math.cos(start_r)
    y1 = cy + r * math.sin(start_r)
    x2 = cx + r * math.cos(end_r)
    y2 = cy + r * math.sin(end_r)
    large = 1 if deg > 180 else 0
    segs.append(f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large},1 {x2:.2f},{y2:.2f} Z" fill="{color}" opacity="0.9"/>')
    offset += deg
if not segs:
    segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="#22c55e"/>')
print("".join(segs))
PYEOF
)

    # Parse markdown sections into HTML findings using Python
    local findings_html
    findings_html=$(python3 - "$REPORT_FILE" <<'PYEOF' 2>/dev/null || echo "<p>Install Python 3 to view structured findings. The full report is available in the Markdown file.</p>"
import sys, re, html

with open(sys.argv[1], encoding='utf-8', errors='replace') as f:
    content = f.read()

# Extract everything between the first --- (after header table) and the end of recommendations
body_match = re.search(r'---\s*\n(.*)', content, re.DOTALL)
body = body_match.group(1) if body_match else content

# Split into h2 sections
sections = re.split(r'(?=^## )', body, flags=re.MULTILINE)
output = []

severity_class = {
    'CRITICAL': 'critical', 'HIGH': 'high',
    'MEDIUM':   'medium',   'LOW':  'low', 'INFO': 'info'
}

for section in sections:
    lines = section.strip().splitlines()
    if not lines:
        continue
    header = lines[0].strip()
    if header.startswith('## Executive Summary') or header.startswith('## Table of'):
        continue
    if header.startswith('## '):
        section_title = re.sub(r'^#+\s*', '', header)
        output.append(f'<div class="section"><h2>{html.escape(section_title)}</h2>')

        # Find all h4 findings within this section
        findings = re.split(r'(?=^#### )', section, flags=re.MULTILINE)
        clean_intro = findings[0] if findings else ''
        # Render intro text (skip the h2 line itself)
        intro_lines = clean_intro.splitlines()[1:]
        intro_text = '\n'.join(intro_lines).strip()
        if intro_text and 'No issues' in intro_text:
            output.append('<p class="clean">✅ No issues found in this section.</p>')
        elif intro_text:
            # Light prose rendering
            intro_html = html.escape(intro_text)
            output.append(f'<div class="section-intro">{intro_html}</div>')

        for finding in findings[1:]:
            f_lines = finding.strip().splitlines()
            if not f_lines:
                continue
            f_header = f_lines[0]
            # Extract severity and title
            sev_match = re.search(r'\*\*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\*\*\s*[—-]\s*(.*)', f_header)
            if not sev_match:
                continue
            sev = sev_match.group(1)
            title = html.escape(sev_match.group(2).strip())
            css_cls = severity_class.get(sev, 'info')

            body_text = '\n'.join(f_lines[1:])

            # Extract details block
            det_match = re.search(r'```\n(.*?)```', body_text, re.DOTALL)
            details_block = ''
            if det_match:
                details_block = f'<pre class="details-pre">{html.escape(det_match.group(1).strip())}</pre>'

            # Extract recommendation
            rec_match = re.search(r'\*\*Recommendation:\*\*\s*(.*)', body_text)
            rec_html = ''
            if rec_match:
                rec_html = f'<div class="rec">💡 {html.escape(rec_match.group(1).strip())}</div>'

            # Description: everything before <details>
            desc_raw = re.sub(r'<details>.*?</details>', '', body_text, flags=re.DOTALL)
            desc_raw = re.sub(r'> \*\*Recommendation:.*', '', desc_raw)
            desc = html.escape(desc_raw.strip())

            output.append(f'''
<div class="finding {css_cls}">
  <div class="finding-header">
    <span class="badge {css_cls}">{sev}</span>
    <span class="finding-title">{title}</span>
  </div>
  <div class="finding-body">
    {f'<p>{desc}</p>' if desc else ''}
    {details_block}
    {rec_html}
  </div>
</div>''')
        output.append('</div>')

print(''.join(output))
PYEOF
)

    # Build scan metadata
    local scan_date hostname_val
    scan_date=$(date '+%B %d, %Y at %H:%M:%S %Z')
    hostname_val=$(hostname 2>/dev/null || echo "N/A")
    local duration_text="${DURATION_MIN}m ${DURATION_SEC}s"
    local files_scanned
    files_scanned=$(wc -l < "$FILE_LIST" 2>/dev/null || echo 0)

    cat > "$html_file" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — $(basename "$SCAN_DIR")</title>
<style>
/* ── Reset & Base ────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:15px;line-height:1.6;background:#f1f5f9;color:#1e293b}
a{color:#3b82f6}
/* ── Layout ──────────────────────────────────────────────────────── */
.container{max-width:1100px;margin:0 auto;padding:24px 16px}
/* ── Header ──────────────────────────────────────────────────────── */
header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);color:#f8fafc;padding:32px 40px;border-radius:12px;margin-bottom:24px;display:flex;align-items:center;gap:20px}
header .shield{font-size:48px}
header h1{font-size:26px;font-weight:700;letter-spacing:-0.5px}
header .subtitle{font-size:14px;color:#94a3b8;margin-top:4px}
/* ── Summary Grid ────────────────────────────────────────────────── */
.summary-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:24px}
@media(max-width:720px){.summary-grid{grid-template-columns:1fr}}
.card{background:#fff;border-radius:10px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.card-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:#64748b;margin-bottom:16px}
/* ── Score Gauge ─────────────────────────────────────────────────── */
.gauge-wrap{display:flex;flex-direction:column;align-items:center}
.gauge-wrap svg{width:200px;height:110px;overflow:visible}
.gauge-grade{font-size:36px;font-weight:800;color:${grade_color};margin-top:4px}
.gauge-label{font-size:13px;color:#64748b}
/* ── Donut Chart ─────────────────────────────────────────────────── */
.donut-wrap{display:flex;flex-direction:column;align-items:center}
.donut-wrap svg{width:130px;height:130px}
.donut-legend{display:flex;flex-direction:column;gap:6px;margin-top:12px;width:100%}
.legend-item{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.legend-count{margin-left:auto;font-weight:600}
/* ── Severity Counts ─────────────────────────────────────────────── */
.sev-list{display:flex;flex-direction:column;gap:10px}
.sev-row{display:flex;align-items:center;gap:10px;font-size:14px}
.sev-bar-bg{flex:1;background:#f1f5f9;border-radius:4px;height:8px;overflow:hidden}
.sev-bar-fill{height:100%;border-radius:4px}
.sev-count{font-weight:700;min-width:28px;text-align:right}
/* ── Meta Table ──────────────────────────────────────────────────── */
.meta-table{width:100%;border-collapse:collapse;font-size:14px}
.meta-table tr:not(:last-child) td{border-bottom:1px solid #f1f5f9}
.meta-table td{padding:8px 4px}
.meta-table td:first-child{color:#64748b;white-space:nowrap;width:150px}
.meta-table td:last-child{font-weight:500;word-break:break-all}
/* ── Findings ────────────────────────────────────────────────────── */
.section{background:#fff;border-radius:10px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:16px}
.section h2{font-size:17px;font-weight:700;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #f1f5f9}
.clean{color:#16a34a;font-size:14px}
.section-intro{font-size:14px;color:#64748b;margin-bottom:12px;white-space:pre-wrap}
.finding{border:1px solid #e2e8f0;border-radius:8px;margin-bottom:12px;overflow:hidden}
.finding-header{padding:10px 14px;display:flex;align-items:center;gap:10px;cursor:pointer;background:#fafafa}
.finding-header:hover{background:#f1f5f9}
.finding-body{padding:12px 14px;border-top:1px solid #e2e8f0;display:none}
.finding.open .finding-body{display:block}
.finding-title{font-size:14px;font-weight:600}
.badge{font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;letter-spacing:.4px;flex-shrink:0}
.badge.critical,.finding.critical .finding-header{background:#fef2f2}.badge.critical{color:#dc2626;border:1px solid #fca5a5}
.badge.high,.finding.high .finding-header{background:#fff7ed}.badge.high{color:#ea580c;border:1px solid #fdba74}
.badge.medium,.finding.medium .finding-header{background:#fffbeb}.badge.medium{color:#d97706;border:1px solid #fde68a}
.badge.low,.finding.low .finding-header{background:#eff6ff}.badge.low{color:#2563eb;border:1px solid #93c5fd}
.badge.info,.finding.info .finding-header{background:#f8fafc}.badge.info{color:#64748b;border:1px solid #cbd5e1}
.details-pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;margin:8px 0;white-space:pre-wrap;word-break:break-all}
.rec{background:#f0fdf4;border-left:3px solid #22c55e;padding:8px 12px;border-radius:0 6px 6px 0;font-size:13px;margin-top:8px}
.finding p{font-size:14px;color:#475569;margin-bottom:8px}
/* ── Severity colours ────────────────────────────────────────────── */
.col-crit{color:#dc2626}.col-high{color:#ea580c}.col-med{color:#d97706}.col-low{color:#2563eb}.col-info{color:#64748b}
.fill-crit{background:#ef4444}.fill-high{background:#f97316}.fill-med{background:#f59e0b}.fill-low{background:#3b82f6}.fill-info{background:#6b7280}
/* ── Risk Badge ──────────────────────────────────────────────────── */
.risk-banner{text-align:center;font-size:18px;font-weight:700;padding:10px;border-radius:6px;margin:12px 0}
.risk-CRITICAL{background:#fef2f2;color:#dc2626}
.risk-HIGH{background:#fff7ed;color:#ea580c}
.risk-MEDIUM{background:#fffbeb;color:#d97706}
.risk-LOW{background:#eff6ff;color:#2563eb}
.risk-CLEAN{background:#f0fdf4;color:#16a34a}
/* ── Footer ──────────────────────────────────────────────────────── */
footer{text-align:center;font-size:12px;color:#94a3b8;padding:24px 0 8px}
/* ── Print ───────────────────────────────────────────────────────── */
@media print{
  body{background:#fff}
  header{border-radius:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .finding-body{display:block!important}
  .finding-header{cursor:default}
}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<header>
  <div class="shield">🛡️</div>
  <div>
    <h1>Website Security Scan Report</h1>
    <div class="subtitle">Universal Web Security Scanner v3.0 · Malware · Vulnerability · Configuration Audit</div>
  </div>
</header>

<!-- Summary Grid -->
<div class="summary-grid">

  <!-- Score Gauge -->
  <div class="card">
    <div class="card-title">Security Score</div>
    <div class="gauge-wrap">
      <svg viewBox="0 0 200 110" xmlns="http://www.w3.org/2000/svg">
        <!-- Background track -->
        <path d="M20,100 A80,80 0 0,1 180,100" fill="none" stroke="#e2e8f0" stroke-width="16" stroke-linecap="round"/>
        <!-- Score arc -->
        <path d="${gauge_arc}" fill="none" stroke="${grade_color}" stroke-width="16" stroke-linecap="round"/>
        <!-- Score text -->
        <text x="100" y="88" text-anchor="middle" font-size="30" font-weight="800" fill="${grade_color}" font-family="system-ui,sans-serif">${SECURITY_SCORE}</text>
        <text x="100" y="106" text-anchor="middle" font-size="12" fill="#94a3b8" font-family="system-ui,sans-serif">out of 100</text>
      </svg>
      <div class="gauge-grade">${SECURITY_GRADE}</div>
      <div class="gauge-label">$(get_grade_description "$SECURITY_GRADE")</div>
    </div>
  </div>

  <!-- Donut Chart -->
  <div class="card">
    <div class="card-title">Issue Breakdown</div>
    <div class="donut-wrap">
      <svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
        ${donut_segments}
        <circle cx="60" cy="60" r="28" fill="white"/>
        <text x="60" y="56" text-anchor="middle" font-size="18" font-weight="800" fill="#1e293b" font-family="system-ui,sans-serif">${TOTAL_ISSUES}</text>
        <text x="60" y="70" text-anchor="middle" font-size="9" fill="#94a3b8" font-family="system-ui,sans-serif">TOTAL</text>
      </svg>
      <div class="donut-legend">
        <div class="legend-item"><span class="legend-dot" style="background:#ef4444"></span>Critical<span class="legend-count col-crit">${CRITICAL}</span></div>
        <div class="legend-item"><span class="legend-dot" style="background:#f97316"></span>High<span class="legend-count col-high">${HIGH}</span></div>
        <div class="legend-item"><span class="legend-dot" style="background:#f59e0b"></span>Medium<span class="legend-count col-med">${MEDIUM}</span></div>
        <div class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span>Low<span class="legend-count col-low">${LOW}</span></div>
        <div class="legend-item"><span class="legend-dot" style="background:#6b7280"></span>Info<span class="legend-count col-info">${INFO}</span></div>
      </div>
    </div>
  </div>

  <!-- Scan Info -->
  <div class="card">
    <div class="card-title">Scan Details</div>
    <table class="meta-table">
      <tr><td>Target</td><td><code>${SCAN_DIR}</code></td></tr>
      <tr><td>Date</td><td>${scan_date}</td></tr>
      <tr><td>Hostname</td><td>${hostname_val}</td></tr>
      <tr><td>Frameworks</td><td>${FW_LIST}</td></tr>
      <tr><td>Duration</td><td>${duration_text}</td></tr>
      <tr><td>Files scanned</td><td>${files_scanned}</td></tr>
      <tr><td>Scan mode</td><td>${SCAN_MODE}</td></tr>
    </table>
    <div class="risk-banner risk-$(echo "$RISK_LEVEL" | grep -oE 'CRITICAL|HIGH|MEDIUM|LOW|CLEAN')">${RISK_LEVEL}</div>
  </div>

</div><!-- /summary-grid -->

<!-- Severity Bars -->
<div class="card" style="margin-bottom:24px">
  <div class="card-title">Severity Distribution</div>
  <div class="sev-list">
HTMLEOF

    # Add severity bars
    local max_count=$(( CRITICAL > HIGH ? CRITICAL : HIGH ))
    max_count=$(( max_count > MEDIUM ? max_count : MEDIUM ))
    max_count=$(( max_count > LOW ? max_count : LOW ))
    max_count=$(( max_count > INFO ? max_count : INFO ))
    [[ "$max_count" -eq 0 ]] && max_count=1

    for sev_info in "CRITICAL:${CRITICAL}:crit:#ef4444" "HIGH:${HIGH}:high:#f97316" "MEDIUM:${MEDIUM}:med:#f59e0b" "LOW:${LOW}:low:#3b82f6" "INFO:${INFO}:info:#6b7280"; do
        local name count cls color pct
        IFS=: read -r name count cls color <<< "$sev_info"
        pct=$(( count * 100 / max_count ))
        cat >> "$html_file" <<BAREOF
    <div class="sev-row">
      <span style="width:70px;font-size:13px;font-weight:600" class="col-${cls}">${name}</span>
      <div class="sev-bar-bg"><div class="sev-bar-fill fill-${cls}" style="width:${pct}%"></div></div>
      <span class="sev-count col-${cls}">${count}</span>
    </div>
BAREOF
    done

    cat >> "$html_file" <<HTMLEOF
  </div>
</div>

<!-- Findings -->
<div id="findings">
${findings_html}
</div>

<footer>
  <p>Generated by <strong>Universal Web Security Scanner v3.0</strong> · ${scan_date}</p>
  <p style="margin-top:4px">Automated scan — manual review of flagged items is recommended.</p>
</footer>

</div><!-- /container -->

<script>
// Collapsible findings
document.querySelectorAll('.finding-header').forEach(h => {
  h.addEventListener('click', () => {
    h.closest('.finding').classList.toggle('open');
  });
});
// Auto-open critical and high findings
document.querySelectorAll('.finding.critical, .finding.high').forEach(f => {
  f.classList.add('open');
});
</script>
</body>
</html>
HTMLEOF

    ok "HTML report saved to: ${html_file}"
    HTML_REPORT_FILE="$html_file"
}
