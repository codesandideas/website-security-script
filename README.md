# 🔒 Universal Web Security Scanner v3.0

A comprehensive bash-based security auditing tool that scans websites and web applications for malware, vulnerabilities, misconfigurations, and security issues across multiple frameworks and platforms.

## ✨ Features

- **Multi-Framework Support**: Automatically detects and audits WordPress, Laravel, Drupal, Joomla, Magento, CodeIgniter, Node.js/Express, Django, Flask, Next.js, Ruby on Rails, and static sites
- **Comprehensive Malware Detection**: Scans for web shells, backdoors, crypto miners, SEO spam, and malicious code injections
- **Vulnerability Assessment**: Identifies SQL injection patterns, XSS vulnerabilities, insecure file permissions, and configuration issues
- **Code Obfuscation Detection**: Finds suspicious base64 encoding, hex encoding, and PHP obfuscation techniques
- **Framework-Specific Audits**: Performs targeted security checks based on detected frameworks
- **Dependency Scanning**: Checks outdated and vulnerable packages across npm, Composer, pip, and Bundler
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

## 🚀 Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/codesandideas/website-security-script/main/website-security-script.sh
```

2. Make it executable:
```bash
chmod +x website-security-script.sh
```

3. Run with sudo privileges:
```bash
sudo bash website-security-script.sh /path/to/website
```

## 📖 Usage

### Basic Scan

Scan a website directory and generate a local report:

```bash
sudo bash website-security-script.sh /var/www/html
```

### Scan with Webhook Notification

Send the security report to a remote endpoint:

```bash
sudo bash website-security-script.sh /var/www/html \
  --webhook https://yourdomain.com/security-receiver.php \
  --api-key YOUR_SECRET_KEY \
  --email admin@example.com
```

### Command-Line Options

```
Usage: sudo bash website-security-script.sh <path> [options]

Arguments:
  <path>              Path to the website root directory

Options:
  --webhook <url>     Send report to a webhook endpoint via POST
  --api-key <key>     API key for webhook authentication
  --email <address>   Recipient email (passed to webhook)
  --help              Show help message
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

## 📝 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║                       SCAN COMPLETE                            ║
╚══════════════════════════════════════════════════════════════════╝

Frameworks     : WordPress, Node.js
Risk Level     : 🟠 High Risk
Total Issues   : 23
  Critical : 2
  High     : 8
  Medium   : 10
  Low      : 3
  Info     : 0

Report saved to: security-report_2026-02-19_12-00-00.md
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is open source and available for use in securing web applications.

## ⚠️ Disclaimer

This security scanner is provided as-is for educational and security auditing purposes. Always obtain proper authorization before scanning systems you do not own. The authors are not responsible for misuse or any damages caused by this tool.
