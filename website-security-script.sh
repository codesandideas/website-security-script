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
# Output: Markdown report (security-report_YYYY-MM-DD_HH-MM-SS.md)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/helpers.sh"
source "$SCRIPT_DIR/lib/cron.sh"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/framework.sh"
source "$SCRIPT_DIR/lib/report.sh"
source "$SCRIPT_DIR/lib/webhook.sh"

# Source all scan modules
for f in "$SCRIPT_DIR"/scans/[0-9][0-9]_*.sh; do source "$f"; done

# Run
parse_args "$@"
validate_input
detect_frameworks
init_report

# Parallel scan
run_parallel_scans

# Post-scan
generate_summary
write_recommendations
send_webhook
final_output
