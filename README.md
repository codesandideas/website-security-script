# Security Scan Report Receiver

A standalone PHP endpoint that receives security scan reports via POST and delivers them via email with beautiful HTML formatting. Designed to work with web security scanners to centralize vulnerability reporting.

## 🎯 Features

- **📧 Email Delivery**: Sends beautifully formatted HTML emails with scan results
- **🔐 API Key Authentication**: Secure endpoint with timing-safe API key comparison
- **📊 Rich Report Formatting**: Converts Markdown reports to styled HTML with syntax highlighting
- **💾 Local Storage**: Optionally saves reports to disk for archival
- **🚦 Rate Limiting**: Built-in file-based rate limiting to prevent abuse
- **🌐 IP Whitelisting**: Optional IP-based access control
- **📮 SMTP Support**: Built-in SMTP client (no dependencies) or PHP mail()
- **🎨 Responsive Design**: Mobile-friendly email templates with severity-based color coding
- **📎 Attachments**: Includes Markdown report as email attachment
- **📝 Comprehensive Logging**: Tracks all requests, successes, and failures

## 📋 Requirements

- PHP 7.4 or higher
- Web server (Apache, Nginx, or similar)
- Mail server or SMTP credentials (for email delivery)

## 🚀 Installation

1. **Upload the script** to your web server:
   ```bash
   # Upload website-security-script.sh to your server
   scp website-security-script.sh user@yourserver.com:/var/www/html/security-receiver.php
   ```

2. **Set appropriate permissions**:
   ```bash
   chmod 640 /var/www/html/security-receiver.php
   ```

3. **Create reports directory** (if using local storage):
   ```bash
   mkdir /var/www/html/security-reports
   chmod 750 /var/www/html/security-reports
   ```

4. **Configure the script** (see Configuration section below)

## ⚙️ Configuration

Edit the `$config` array at the top of the script:

### Authentication

```php
'api_key' => 'CHANGE_THIS_TO_A_STRONG_RANDOM_KEY',
```
**Important**: Change this to a strong, random string before deployment.

### Email Settings

```php
'from_name'         => 'Security Scanner',
'from_email'        => 'scanner@yourdomain.com',
'default_recipient' => 'admin@yourdomain.com',  // Fallback if no email in request
```

### SMTP Configuration (Optional)

To use SMTP instead of PHP's `mail()` function:

```php
'smtp_enabled'   => true,
'smtp_host'      => 'smtp.gmail.com',
'smtp_port'      => 587,
'smtp_encryption' => 'tls',  // 'tls' or 'ssl'
'smtp_username'  => 'your-email@gmail.com',
'smtp_password'  => 'your-app-password',  // Use App Password for Gmail
```

**Gmail Setup**: For Gmail, you need to:
1. Enable 2-factor authentication
2. Generate an [App Password](https://support.google.com/accounts/answer/185833)
3. Use the App Password in the configuration

### Security Settings

```php
'allowed_ips'    => [],           // Empty = allow all. Ex: ['1.2.3.4', '5.6.7.8']
'rate_limit'     => 10,           // Max requests per hour per IP
'max_payload_mb' => 10,           // Max POST size in MB
```

### Storage Settings

```php
'save_reports' => true,                              // Save reports to disk
'report_dir'   => __DIR__ . '/security-reports',    // Directory for reports
'log_file'     => __DIR__ . '/security-receiver.log', // Log file path
```

## 📤 Usage

### Testing the Endpoint

Test that the endpoint is working:

```bash
curl -X GET https://yourdomain.com/security-receiver.php
```

Expected response:
```json
{
  "status": "success",
  "message": "Security Scan Report Receiver is running",
  "version": "1.0"
}
```

### Sending a Test Report

```bash
curl -X POST https://yourdomain.com/security-receiver.php \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "YOUR_SECRET_KEY",
    "email": "admin@example.com",
    "hostname": "web01.example.com",
    "scan_target": "/var/www/html",
    "risk_level": "MEDIUM",
    "frameworks": "WordPress 6.4, PHP 8.1",
    "total_issues": 5,
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 1,
    "info": 0,
    "report": "# Security Scan Report\n\n## Summary\n\nFound 5 security issues.\n\n## Issues\n\n- SQL Injection risk in login.php\n- Outdated library detected"
  }'
```

### Integration with Security Scanners

Example usage with a hypothetical security scanner:

```bash
sudo bash web-security-scanner.sh /var/www/html \
  --webhook https://yourdomain.com/security-receiver.php \
  --api-key YOUR_SECRET_KEY \
  --email admin@yoursite.com
```

## 📡 API Reference

### Endpoint: POST /

Receives and processes security scan reports.

#### Request Headers

```
Content-Type: application/json
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | string | ✅ | Authentication key (must match config) |
| `report` | string | ✅ | Markdown-formatted security report |
| `email` | string | ⚪ | Recipient email (falls back to default_recipient) |
| `hostname` | string | ⚪ | Server hostname |
| `scan_target` | string | ⚪ | Path or URL that was scanned |
| `risk_level` | string | ⚪ | Overall risk: CRITICAL, HIGH, MEDIUM, LOW, CLEAN |
| `frameworks` | string | ⚪ | Detected frameworks/technologies |
| `total_issues` | integer | ⚪ | Total number of issues found |
| `critical` | integer | ⚪ | Number of critical issues |
| `high` | integer | ⚪ | Number of high severity issues |
| `medium` | integer | ⚪ | Number of medium severity issues |
| `low` | integer | ⚪ | Number of low severity issues |
| `info` | integer | ⚪ | Number of informational items |

#### Response

**Success (200)**:
```json
{
  "status": "success",
  "message": "Report received and emailed successfully",
  "emailed_to": "admin@example.com",
  "risk_level": "MEDIUM",
  "issues": 5,
  "saved": true
}
```

**Authentication Error (401)**:
```json
{
  "status": "error",
  "message": "Invalid API key"
}
```

**Rate Limited (429)**:
```json
{
  "status": "error",
  "message": "Rate limit exceeded. Try again later."
}
```

**Partial Success (207)**: Report saved but email failed
```json
{
  "status": "success",
  "message": "Report saved locally but email failed",
  "error": "SMTP connection timeout",
  "saved": true
}
```

## 🎨 Email Template Features

The generated emails include:

- **Modern, Responsive Design**: Works on desktop and mobile
- **Risk Level Badges**: Color-coded (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, CLEAN=green)
- **Statistics Dashboard**: Visual summary of issues by severity
- **Markdown Rendering**: Supports headers, lists, tables, code blocks, and more
- **Syntax Highlighting**: Code blocks with dark theme styling
- **Tables**: Automatically styled with alternating rows
- **Expandable Sections**: Support for HTML `<details>` elements
- **Markdown Attachment**: Full report included as `.md` file

## 🔍 Supported Markdown Features

The report converter supports:

- **Headers** (`#`, `##`, `###`, `####`)
- **Bold** (`**text**`) and *Italic* (`*text*`)
- **Code blocks** (` ```language ... ``` `)
- **Inline code** (`` `code` ``)
- **Tables** (GitHub-flavored)
- **Lists** (ordered and unordered)
- **Checkboxes** (`- [ ]` and `- [x]`)
- **Blockquotes** (`> text`) - styled as recommendation boxes
- **Links** (`[text](url)`)
- **Horizontal rules** (`---`)
- **Details/Summary** (`<details><summary>...</summary>...</details>`)

## 🛡️ Security Considerations

1. **Change the default API key** immediately after installation
2. **Use HTTPS** to encrypt data in transit
3. **Restrict file permissions**: `chmod 640` on the PHP file
4. **Enable IP whitelisting** if possible
5. **Review rate limits** based on your expected traffic
6. **Secure the reports directory** with `.htaccess` (automatically created)
7. **Monitor logs** regularly for suspicious activity
8. **Use App Passwords** for Gmail SMTP (not your account password)

## 📊 Logging

Logs are stored in the file specified by `$config['log_file']` (default: `security-receiver.log`)

Log format:
```
[2024-02-19 10:30:45] [INFO] [192.168.1.100] Report received: web01.example.com | Risk: MEDIUM | Issues: 5 (C:0 H:1 M:3)
[2024-02-19 10:30:46] [INFO] [192.168.1.100] Email sent to admin@example.com
[2024-02-19 10:30:46] [INFO] [192.168.1.100] Saved: scan_web01_2024-02-19_10-30-45.md
```

## 🐛 Troubleshooting

### Email Not Sending

**Problem**: Email delivery fails

**Solutions**:
1. Check PHP's `mail()` configuration: `php -i | grep mail`
2. Verify SMTP credentials if using SMTP
3. Check error logs: `tail -f security-receiver.log`
4. For Gmail: Ensure you're using an App Password, not your account password
5. Test with a simple PHP mail script to isolate the issue

### 401 Unauthorized

**Problem**: API key rejected

**Solutions**:
1. Verify the API key matches exactly (case-sensitive)
2. Check for whitespace or encoding issues
3. Review logs for authentication attempts

### 429 Rate Limited

**Problem**: Too many requests

**Solutions**:
1. Increase `rate_limit` in config
2. Wait one hour for the rate limit to reset
3. Check `/tmp/secrecv_rate_*` files for rate limit data

### Reports Not Saved

**Problem**: `saved: false` in response

**Solutions**:
1. Ensure `save_reports` is `true`
2. Check directory permissions: `chmod 750 security-reports`
3. Verify web server has write access to the directory
4. Check disk space: `df -h`

### IP Blocked

**Problem**: 403 Forbidden

**Solutions**:
1. Add your IP to `allowed_ips` array
2. Set `allowed_ips` to empty array `[]` to allow all IPs
3. Check proxy/load balancer configuration for correct IP forwarding

## 📝 File Storage Structure

When `save_reports` is enabled, reports are saved as:

```
security-reports/
├── .htaccess (auto-generated, denies web access)
├── scan_web01_2024-02-19_10-30-45.md
├── scan_web02_2024-02-19_11-15-23.md
└── scan_database_2024-02-19_14-22-10.md
```

## 🔄 Version History

- **v1.0** - Initial release
  - Email delivery with HTML formatting
  - API key authentication
  - Rate limiting
  - Local storage
  - SMTP support
  - Markdown to HTML conversion

## 📄 License

This script is provided as-is for security monitoring purposes. Review and customize according to your needs.

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the log file for error details
3. Verify all configuration settings
4. Test with the provided curl examples

---

**Generated by**: Universal Web Security Scanner v3.0  
**Note**: Always manually review flagged security items before taking action.
