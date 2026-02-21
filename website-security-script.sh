#!/bin/bash
# ============================================================================
# Universal Web Security Scanner v3.0
# Comprehensive Malware, Vulnerability & Configuration Auditor
# Supports: WordPress, Laravel, Drupal, Joomla, Magento, CodeIgniter,
#           Node.js/Express, Django, Flask, Next.js, Static Sites, and more
#
# Usage: webscan /path/to/website [options]
# Install: sudo bash install.sh
#
# Output: Markdown report (always) + optional HTML, JSON, SARIF
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/helpers.sh"
source "$SCRIPT_DIR/lib/cron.sh"
source "$SCRIPT_DIR/lib/fix.sh"
source "$SCRIPT_DIR/lib/baseline.sh"
source "$SCRIPT_DIR/lib/email.sh"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/framework.sh"
source "$SCRIPT_DIR/lib/wp_integrity.sh"
source "$SCRIPT_DIR/lib/allowlist.sh"
source "$SCRIPT_DIR/lib/report.sh"
source "$SCRIPT_DIR/lib/html_report.sh"
source "$SCRIPT_DIR/lib/output_formats.sh"
source "$SCRIPT_DIR/lib/webhook.sh"

# Source all scan modules
for f in "$SCRIPT_DIR"/scans/[0-9][0-9]_*.sh; do source "$f"; done

# Run
parse_args "$@"

# ── Baseline mode: save/compare/list/delete (exits inside) ─────────────────
run_baseline_mode

validate_input
detect_frameworks
init_report

# Parallel scan
run_parallel_scans

# Post-scan: summary + markdown report finalised here
generate_summary
write_recommendations

# ── Additional output formats ───────────────────────────────────────────────
export_report_env
for fmt in "${OUTPUT_FORMATS[@]}"; do
    case "$fmt" in
        html)  generate_html_report ;;
        json)  generate_json_report ;;
        sarif) generate_sarif_report ;;
    esac
done

# ── Notifications ───────────────────────────────────────────────────────────
send_webhook
send_email

# ── Auto-remediation (runs after report so fixes are logged against findings)
run_fix_mode

final_output
