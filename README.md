# 🔒 Universal Web Security Scanner v3.0

A comprehensive bash-based security auditing tool that scans websites and web applications for malware, vulnerabilities, misconfigurations, and security issues across multiple frameworks and platforms.

## ✨ Features

- **Multi-Framework Support**: Automatically detects and audits WordPress, Laravel, Drupal, Joomla, Magento, CodeIgniter, Node.js/Express, Django, Flask, Next.js, Ruby on Rails, and static sites
- **Comprehensive Malware Detection**: Scans for web shells, backdoors, crypto miners, SEO spam, and malicious code injections
- **Vulnerability Assessment**: Identifies SQL injection patterns, XSS vulnerabilities, insecure file permissions, and configuration issues
- **Code Obfuscation Detection**: Finds suspicious base64 encoding, hex encoding, and PHP obfuscation techniques
- **Framework-Specific Audits**: Performs targeted security checks based on detected frameworks
- **Dependency Scanning**: Checks outdated and vulnerable packages across npm, Composer, pip, and Bundler
- **Security Score & Grading**: Calculates a 0–100 security score with letter grades (A+ through F) based on findings
- **Background Scanning**: Run scans detached from the terminal — survives terminal close
- **Scheduled Scans (Cron)**: Set up recurring scans with simple shortcuts or custom cron expressions
- **Persistent Configuration**: Save default email, webhook, API key, and scan settings in a config file
- **Email Notifications**: Send scan results via email (configurable per-scan or as default)
- **Webhook Integration**: Sends security reports to remote endpoints via POST requests
- **Markdown Reports**: Generates timestamped, detailed security reports in Markdown format
- **Risk Classification**: Issues categorized by severity (Critical, High, Medium, Low, Info)

## 🎯 Supported Platforms

| Platform | Detection | Framework-Specific Checks |
|----------|-----------|---------------------------|
| WordPress | ✅ | Version check, debug mode, file permissions, security keys, plugins, themes |
| Laravel | ✅ | Debug mode, environment, APP_KEY, database security, CSRF protection |
| Drupal | ✅ | Core files, configuration, security settings |
| Joomla | ✅ | Configuration, security settings |
| Magento | ✅ | E-commerce security checks |
| Node.js/Express/Next.js | ✅ | Dependencies, security patterns, backdoor detection |
| Django | ✅ | Settings.py security, debug mode, secret keys |
| Flask | ✅ | Configuration security, debug mode |
| Ruby on Rails | ✅ | Configuration, security settings |
| CodeIgniter | ✅ | Framework detection |
| Static Sites | ✅ | Generic security checks |

## 📋 Requirements

- **Operating System**: Linux/Unix-based system
- **Bash**: Version 4.0 or higher
- **Root Access**: Required (`sudo`) for comprehensive file system scanning
- **Optional Tools**:
  - `curl` - For webhook integration
  - `python` or `python3` - For JSON payload formatting (webhook feature)
  - `php` - For PHP configuration analysis
  - `node` - For Node.js runtime analysis
  - `crontab` - For scheduled scans (`--cron`)

## 🚀 Installation

### Quick Install (Global Command)

```bash
sudo bash install.sh
```

This installs the scanner as `webscan` in `/usr/local/bin` and creates a default config file at `~/.config/webscan/config`.

### Manual

```bash
chmod +x website-security-script.sh
sudo bash website-security-script.sh /path/to/website
```

### Uninstall

```bash
sudo bash uninstall.sh
```

## 📖 Usage

### Basic Scan

```bash
webscan /var/www/html
```

### Background Scan

Run a scan that continues even after closing the terminal:

```bash
webscan /var/www/html --background
```

Output is logged to `~/.config/webscan/logs/scan_<timestamp>.log`. Monitor with:

```bash
tail -f ~/.config/webscan/logs/scan_*.log
```

### Scheduled Scans (Cron)

Set up recurring scans using shortcuts or custom cron expressions:

```bash
# Built-in shortcuts
webscan /var/www/html --cron hourly        # Every hour
webscan /var/www/html --cron daily         # Every day at 2 AM
webscan /var/www/html --cron weekly        # Every Sunday at 2 AM
webscan /var/www/html --cron monthly       # 1st of each month at 2 AM

# Custom cron expression
webscan /var/www/html --cron '30 3 * * 1-5'   # Weekdays at 3:30 AM

# With email notification
webscan /var/www/html --cron daily --email admin@example.com
```

Manage cron jobs:

```bash
webscan --list-cron      # Show active webscan cron jobs
webscan --remove-cron    # Remove all webscan cron jobs
```

### Scan with Webhook Notification

```bash
webscan /var/www/html \
  --webhook https://yourdomain.com/security-receiver.php \
  --api-key YOUR_SECRET_KEY \
  --email admin@example.com
```

### Command-Line Options

```
Usage: webscan <path> [options]

Arguments:
  <path>                    Path to the website root directory

Scan Options:
  --webhook <url>           Send report to a webhook endpoint via POST
  --api-key <key>           API key for webhook authentication
  --email <address>         Recipient email for this scan
  --no-email                Skip email notification for this scan
  --no-recommendations      Hide recommendations section from report
  --background              Run scan in background (survives terminal close)
  --cron <schedule>         Set up a cron job for recurring scans
                            Shortcuts: hourly, daily, weekly, monthly
                            Custom:    '0 2 * * *' (cron expression)
  --remove-cron             Remove all webscan cron jobs
  --list-cron               List active webscan cron jobs

Configuration:
  --set-email <address>     Save default email address
  --enable-email            Enable email notifications by default
  --disable-email           Disable email notifications by default
  --set-webhook <url>       Save default webhook URL
  --set-api-key <key>       Save default API key
  --show-config             Show current configuration
  --edit-config             Open config file in editor
  --help                    Show this help message
```

### Configuration

The scanner stores persistent settings in `~/.config/webscan/config`. Set defaults so you don't have to pass options every time:

```bash
webscan --set-email admin@example.com    # Save default email
webscan --enable-email                   # Enable email notifications
webscan --set-webhook https://...        # Save default webhook URL
webscan --set-api-key YOUR_KEY           # Save default API key
webscan --show-config                    # View current configuration
webscan --edit-config                    # Open config in your editor
```

Override any saved default on a per-scan basis:

```bash
webscan /path --email other@mail.com     # Use a different email for this scan
webscan /path --no-email                 # Skip email for this scan
```

## 🔍 Scan Categories

The scanner performs the following security checks:

### 1. **Malware Detection**
- Known web shells (c99, r57, b374k, WSO, etc.)
- PHP backdoor functions (eval, base64_decode, gzinflate, etc.)
- Python reverse shells and backdoors
- Node.js command injection patterns
- Malicious iframes and script injections
- Cryptocurrency miners (Coinhive, CryptoLoot, etc.)
- SEO spam and pharma hack patterns

### 2. **File & Code Analysis**
- Executable files in upload/media directories
- Suspicious filenames (shell.php, backdoor.php, etc.)
- Polyglot files (PHP code hidden in images)
- Obfuscated code (large single-line files)
- SQL injection patterns
- Cross-Site Scripting (XSS) patterns
- Suspicious base64/hex encoding
- PHP obfuscation techniques

### 3. **File System Security**
- Recently created executable files (last 7 days)
- Suspicious symlinks pointing outside web root
- World-writable files and directories
- SUID/SGID files
- Files owned by suspicious users

### 4. **Framework-Specific Audits**

Each detected framework receives targeted security checks:

- **WordPress**: Version check, debug mode, file editor, security keys, SSL enforcement, XML-RPC, plugin/theme vulnerabilities
- **Laravel**: Debug mode, environment settings, APP_KEY, database configuration, CSRF protection, log files
- **Drupal**: Core integrity, configuration security
- **Django**: DEBUG setting, SECRET_KEY, allowed hosts, database security
- **Flask**: Debug mode, secret key configuration
- **Node.js**: Package vulnerabilities, security headers

### 5. **Dependency Scanning**
- npm packages (Node.js)
- Composer packages (PHP)
- pip packages (Python)
- Bundler gems (Ruby)

### 6. **Runtime Configuration**
- PHP configuration (display_errors, file_uploads, open_basedir)
- Node.js runtime security
- Database connection security

### 7. **Server Environment**
- Kernel and OS information
- Running processes analysis
- Port scanning (listening services)

### 8. **Security Score & Grade**

After scanning, the tool calculates a security score (0–100) and assigns a letter grade:

| Grade | Score Range | Meaning |
|-------|------------|---------|
| A+    | 95–100     | Excellent security posture |
| A     | 90–94      | Very good |
| B     | 80–89      | Good, minor issues |
| C     | 70–79      | Fair, notable issues |
| D     | 60–69      | Poor, significant issues |
| F     | 0–59       | Critical, immediate action needed |

## 📤 Webhook Integration

The scanner can POST scan results to a remote webhook endpoint in JSON format:

### Webhook Payload Structure

```json
{
  "api_key": "YOUR_SECRET_KEY",
  "email": "admin@example.com",
  "hostname": "webserver01",
  "scan_target": "/var/www/html",
  "frameworks": "WordPress, Laravel",
  "risk_level": "🔴 Critical Risk",
  "security_grade": "D",
  "security_score": 62,
  "total_issues": 42,
  "critical": 5,
  "high": 12,
  "medium": 15,
  "low": 8,
  "info": 2,
  "report": "# Security Scan Report\n..."
}
```

### Webhook Requirements

- Endpoint must accept POST requests
- Content-Type: `application/json`
- Must return HTTP 200 for successful receipt
- Timeout: 30 seconds

## 📊 Output Format

The scanner generates a Markdown report with the following structure:

```
security-report_YYYY-MM-DD_HH-MM-SS.md
```

### Report Sections

1. **Executive Summary**
   - Scan timestamp and target
   - Detected frameworks
   - Overall risk level
   - Security score and grade
   - Issue statistics

2. **Findings by Category**
   - Malware detection results
   - File & code analysis
   - File system security
   - Framework-specific issues
   - Dependency vulnerabilities
   - Configuration issues

3. **Severity Badges**
   - 🔴 **Critical**: Immediate action required
   - 🟠 **High**: Should be addressed soon
   - 🟡 **Medium**: Important but not urgent
   - 🔵 **Low**: Minor issues
   - ⚪ **Info**: Informational findings

4. **Recommendations**
   - Specific remediation steps for each finding
   - Best practices for each framework

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║          Universal Web Security Scanner v3.0                   ║
║          Malware · Vulnerability · Configuration Audit         ║
╚══════════════════════════════════════════════════════════════════╝

Frameworks     : WordPress, Node.js
Risk Level     : 🟠 High Risk
Security Grade : B (Score: 82/100)
Total Issues   : 23
  Critical : 2
  High     : 8
  Medium   : 10
  Low      : 3
  Info     : 0

Report saved to: security-report_2026-02-19_12-00-00.md
```

## 🛡️ Security Considerations

### Running the Scanner

- **Always backup your data** before running security scans
- Run on a test/staging environment first
- Review findings carefully - false positives are possible
- The scanner is read-only and does not modify files
- Requires root access to scan all files and processes

### Webhook Security

- Use HTTPS endpoints only for webhook URLs
- Implement strong API key validation on the receiving end
- Rotate API keys regularly
- Sanitize and validate all webhook data before processing
- Consider IP whitelisting for webhook endpoints

### Report Handling

- Security reports contain sensitive information
- Store reports securely with appropriate permissions
- Delete old reports or archive them encrypted
- Do not commit reports to version control
- Review who has access to report files

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is open source and available for use in securing web applications.

## ⚠️ Disclaimer

This security scanner is provided as-is for educational and security auditing purposes. Always obtain proper authorization before scanning systems you do not own. The authors are not responsible for misuse or any damages caused by this tool.
