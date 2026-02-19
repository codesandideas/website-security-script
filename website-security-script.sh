<?php
/**
 * ============================================================================
 * Security Scan Report Receiver v1.0
 * Standalone PHP endpoint — receives scan reports via POST and emails them
 *
 * Setup:
 *   1. Upload this file to your server (e.g., https://yourdomain.com/security-receiver.php)
 *   2. Edit the CONFIGURATION section below
 *   3. Set file permissions: chmod 640 security-receiver.php
 *   4. Test: curl -X POST https://yourdomain.com/security-receiver.php \
 *            -H "Content-Type: application/json" \
 *            -d '{"api_key":"YOUR_KEY","email":"test@example.com","report":"# Test","hostname":"test"}'
 *
 * Scanner usage:
 *   sudo bash web-security-scanner.sh /var/www/html \
 *       --webhook https://yourdomain.com/security-receiver.php \
 *       --api-key YOUR_SECRET_KEY \
 *       --email admin@yoursite.com
 * ============================================================================
 */

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION — Edit these values
// ═══════════════════════════════════════════════════════════════════════════════

$config = [
    // Authentication
    'api_key'           => 'CHANGE_THIS_TO_A_STRONG_RANDOM_KEY',

    // Email settings
    'from_name'         => 'Security Scanner',
    'from_email'        => 'scanner@yourdomain.com',
    'default_recipient' => 'admin@yourdomain.com',       // Fallback if no email in request

    // SMTP settings (leave smtp_enabled false to use PHP mail())
    'smtp_enabled'      => false,
    'smtp_host'         => 'smtp.gmail.com',
    'smtp_port'         => 587,
    'smtp_encryption'   => 'tls',                        // 'tls' or 'ssl'
    'smtp_username'     => '',
    'smtp_password'     => '',                            // Use App Password for Gmail

    // Security
    'allowed_ips'       => [],                            // Empty = allow all. Ex: ['1.2.3.4']
    'rate_limit'        => 10,                            // Max requests per hour per IP
    'max_payload_mb'    => 10,                            // Max POST size in MB

    // Storage
    'save_reports'      => true,                          // Save reports to disk
    'report_dir'        => __DIR__ . '/security-reports', // Directory for saved reports
    'log_file'          => __DIR__ . '/security-receiver.log',
];

// ═══════════════════════════════════════════════════════════════════════════════
// DO NOT EDIT BELOW THIS LINE
// ═══════════════════════════════════════════════════════════════════════════════

header('Content-Type: application/json');

// ── Helpers ──────────────────────────────────────────────────────────────────

function respond(int $code, string $message, array $extra = []): void {
    http_response_code($code);
    echo json_encode(array_merge(['status' => $code < 400 ? 'success' : 'error', 'message' => $message], $extra));
    exit;
}

function write_log(string $message, string $level = 'INFO'): void {
    global $config;
    if (empty($config['log_file'])) return;
    $timestamp = date('Y-m-d H:i:s');
    $ip = get_client_ip();
    $line = "[{$timestamp}] [{$level}] [{$ip}] {$message}\n";
    @file_put_contents($config['log_file'], $line, FILE_APPEND | LOCK_EX);
}

function get_client_ip(): string {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = trim(explode(',', $_SERVER[$header])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ── Request Validation ──────────────────────────────────────────────────────

// GET = status page
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    respond(200, 'Security Scan Report Receiver is running', [
        'version'  => '1.0',
        'accepts'  => 'POST with JSON body',
        'required' => ['api_key', 'report'],
        'optional' => ['email', 'hostname', 'scan_target', 'risk_level', 'frameworks',
                        'total_issues', 'critical', 'high', 'medium', 'low', 'info'],
    ]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(405, 'Method not allowed. Use POST.');
}

// IP whitelist
$client_ip = get_client_ip();
if (!empty($config['allowed_ips']) && !in_array($client_ip, $config['allowed_ips'])) {
    write_log("Blocked IP: {$client_ip}", 'WARN');
    respond(403, 'IP not allowed');
}

// Rate limiting (file-based)
$rate_file = sys_get_temp_dir() . '/secrecv_rate_' . md5($client_ip);
$rate_data = @file_get_contents($rate_file);
$rate = $rate_data ? json_decode($rate_data, true) : ['count' => 0, 'window' => time()];

if (time() - $rate['window'] > 3600) {
    $rate = ['count' => 0, 'window' => time()];
}
$rate['count']++;
@file_put_contents($rate_file, json_encode($rate));

if ($rate['count'] > $config['rate_limit']) {
    write_log("Rate limited: {$client_ip} ({$rate['count']} req/hr)", 'WARN');
    respond(429, 'Rate limit exceeded. Try again later.');
}

// Parse JSON body
$raw_body = file_get_contents('php://input');
$max_bytes = $config['max_payload_mb'] * 1024 * 1024;

if (strlen($raw_body) > $max_bytes) {
    respond(413, "Payload too large. Max {$config['max_payload_mb']}MB.");
}

$data = json_decode($raw_body, true);
if (!$data || !is_array($data)) {
    write_log("Invalid JSON received", 'ERROR');
    respond(400, 'Invalid JSON payload');
}

// Validate API key (timing-safe comparison)
if (empty($data['api_key']) || !hash_equals($config['api_key'], $data['api_key'])) {
    write_log("Invalid API key attempt", 'WARN');
    respond(401, 'Invalid API key');
}

// Required fields
if (empty($data['report'])) {
    respond(400, 'Missing required field: report');
}

// ── Extract Data ────────────────────────────────────────────────────────────

$report       = $data['report'];
$email        = filter_var($data['email'] ?? '', FILTER_VALIDATE_EMAIL) ?: $config['default_recipient'];
$hostname     = htmlspecialchars(mb_substr($data['hostname'] ?? 'Unknown Server', 0, 200), ENT_QUOTES, 'UTF-8');
$scan_target  = htmlspecialchars(mb_substr($data['scan_target'] ?? 'N/A', 0, 500), ENT_QUOTES, 'UTF-8');
$risk_level   = htmlspecialchars(mb_substr($data['risk_level'] ?? 'UNKNOWN', 0, 50), ENT_QUOTES, 'UTF-8');
$frameworks   = htmlspecialchars(mb_substr($data['frameworks'] ?? 'N/A', 0, 200), ENT_QUOTES, 'UTF-8');
$total_issues = intval($data['total_issues'] ?? 0);
$critical     = intval($data['critical'] ?? 0);
$high         = intval($data['high'] ?? 0);
$medium       = intval($data['medium'] ?? 0);
$low          = intval($data['low'] ?? 0);
$info         = intval($data['info'] ?? 0);
$scan_date    = date('F j, Y \a\t H:i:s T');

write_log("Report received: {$hostname} | Risk: {$risk_level} | Issues: {$total_issues} (C:{$critical} H:{$high} M:{$medium})");

// ── Save Report to Disk ─────────────────────────────────────────────────────

$saved_file = '';
if ($config['save_reports']) {
    $report_dir = $config['report_dir'];
    if (!is_dir($report_dir)) {
        @mkdir($report_dir, 0750, true);
        @file_put_contents($report_dir . '/.htaccess', "Deny from all\n");
    }

    $safe_host = preg_replace('/[^a-zA-Z0-9._-]/', '_', $data['hostname'] ?? 'unknown');
    $filename  = "scan_{$safe_host}_" . date('Y-m-d_H-i-s') . '.md';
    $filepath  = $report_dir . '/' . $filename;

    if (@file_put_contents($filepath, $report)) {
        $saved_file = $filepath;
        write_log("Saved: {$filename}");
    } else {
        write_log("Failed to save: {$filepath}", 'ERROR');
    }
}

// ── Convert Markdown to HTML ────────────────────────────────────────────────

function md_to_html(string $md): string {
    $h = htmlspecialchars($md, ENT_QUOTES, 'UTF-8');

    // Code blocks
    $h = preg_replace_callback('/```(\w*)\n(.*?)```/s', function ($m) {
        return '<pre style="background:#1e1e2e;color:#cdd6f4;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;line-height:1.5"><code>' . $m[2] . '</code></pre>';
    }, $h);

    // Inline code
    $h = preg_replace('/`([^`]+)`/', '<code style="background:#f1f5f9;color:#be123c;padding:2px 6px;border-radius:4px;font-size:90%">$1</code>', $h);

    // Headers
    $h = preg_replace('/^#### (.+)$/m', '<h4 style="color:#1e293b;margin:20px 0 8px;font-size:15px">$1</h4>', $h);
    $h = preg_replace('/^### (.+)$/m', '<h3 style="color:#1e293b;margin:24px 0 10px;font-size:17px;border-bottom:1px solid #e2e8f0;padding-bottom:6px">$1</h3>', $h);
    $h = preg_replace('/^## (.+)$/m', '<h2 style="color:#0f172a;margin:30px 0 12px;font-size:20px;border-bottom:2px solid #3b82f6;padding-bottom:8px">$1</h2>', $h);
    $h = preg_replace('/^# (.+)$/m', '<h1 style="color:#0f172a;margin:0 0 16px;font-size:26px">$1</h1>', $h);

    // Bold / italic
    $h = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $h);
    $h = preg_replace('/(?<!\*)\*([^*]+)\*(?!\*)/', '<em>$1</em>', $h);

    // Blockquotes (recommendations)
    $h = preg_replace('/^&gt; (.+)$/m',
        '<div style="border-left:4px solid #3b82f6;background:#eff6ff;padding:10px 16px;margin:8px 0;border-radius:0 6px 6px 0;color:#1e40af">$1</div>', $h);

    // Tables
    $h = preg_replace_callback('/(\|.+\|)\n(\|[-| :]+\|)\n((?:\|.+\|\n?)+)/m', function ($m) {
        $headers = array_filter(array_map('trim', explode('|', $m[1])));
        $thead = '<tr>';
        foreach ($headers as $hd) {
            $thead .= '<th style="padding:10px 14px;text-align:left;background:#f8fafc;border-bottom:2px solid #cbd5e1;font-weight:600;color:#334155">' . $hd . '</th>';
        }
        $thead .= '</tr>';

        $tbody = '';
        $i = 0;
        foreach (explode("\n", trim($m[3])) as $row) {
            $cells = array_filter(array_map('trim', explode('|', $row)));
            $bg = ($i++ % 2 === 0) ? '#ffffff' : '#f8fafc';
            $tbody .= '<tr>';
            foreach ($cells as $c) {
                $tbody .= '<td style="padding:8px 14px;border-bottom:1px solid #e2e8f0;background:' . $bg . '">' . $c . '</td>';
            }
            $tbody .= '</tr>';
        }

        return '<table style="border-collapse:collapse;width:100%;margin:12px 0;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">'
            . '<thead>' . $thead . '</thead><tbody>' . $tbody . '</tbody></table>';
    }, $h);

    // Checkboxes
    $h = preg_replace('/- \[ \] (.+)/', '<div style="padding:4px 0"><span style="color:#94a3b8;margin-right:6px">☐</span>$1</div>', $h);
    $h = preg_replace('/- \[x\] (.+)/i', '<div style="padding:4px 0"><span style="color:#22c55e;margin-right:6px">☑</span>$1</div>', $h);

    // Lists
    $h = preg_replace('/^- (.+)$/m', '<div style="padding:3px 0 3px 20px">• $1</div>', $h);
    $h = preg_replace('/^(\d+)\. (.+)$/m', '<div style="padding:3px 0 3px 20px">$1. $2</div>', $h);

    // HR
    $h = preg_replace('/^---+$/m', '<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">', $h);

    // Links
    $h = preg_replace('/\[([^\]]+)\]\(([^)]+)\)/', '<a href="$2" style="color:#2563eb;text-decoration:underline">$1</a>', $h);

    // Details/summary
    $h = str_replace('&lt;details&gt;', '<details style="margin:8px 0;border:1px solid #e2e8f0;border-radius:6px">', $h);
    $h = str_replace('&lt;/details&gt;', '</div></details>', $h);
    $h = preg_replace('/&lt;summary&gt;(.+?)&lt;\/summary&gt;/',
        '<summary style="padding:10px 14px;cursor:pointer;background:#f8fafc;font-weight:500">$1</summary><div style="padding:10px 14px">', $h);

    // Paragraphs
    $h = preg_replace('/\n{2,}/', '</p><p style="margin:8px 0;line-height:1.6">', $h);
    $h = '<p style="margin:8px 0;line-height:1.6">' . $h . '</p>';

    return $h;
}

// ── Build Email HTML ────────────────────────────────────────────────────────

$risk_colors = [
    'CRITICAL' => ['bg' => '#fef2f2', 'border' => '#dc2626', 'badge' => '#dc2626'],
    'HIGH'     => ['bg' => '#fff7ed', 'border' => '#ea580c', 'badge' => '#ea580c'],
    'MEDIUM'   => ['bg' => '#fefce8', 'border' => '#ca8a04', 'badge' => '#ca8a04'],
    'LOW'      => ['bg' => '#eff6ff', 'border' => '#2563eb', 'badge' => '#2563eb'],
    'CLEAN'    => ['bg' => '#f0fdf4', 'border' => '#16a34a', 'badge' => '#16a34a'],
];
$c = $risk_colors[strtoupper($risk_level)] ?? $risk_colors['MEDIUM'];

$report_html = md_to_html($report);

$email_html = <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Security Scan — {$hostname}</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#334155;font-size:14px">
<div style="max-width:800px;margin:0 auto;padding:20px">

<!-- Header -->
<div style="background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff;padding:30px;border-radius:12px 12px 0 0;text-align:center">
    <h1 style="margin:0 0 6px;font-size:22px;font-weight:700">🛡️ Security Scan Report</h1>
    <p style="margin:0;color:#94a3b8;font-size:14px">{$hostname} — {$scan_target}</p>
</div>

<!-- Risk Banner -->
<div style="background:{$c['bg']};border-left:5px solid {$c['border']};padding:20px 24px">
    <span style="display:inline-block;background:{$c['badge']};color:#fff;padding:4px 14px;border-radius:20px;font-size:13px;font-weight:700;letter-spacing:0.5px">{$risk_level}</span>
    <span style="font-weight:600;margin-left:12px;font-size:15px">{$total_issues} issue(s) found</span>
</div>

<!-- Stats -->
<div style="background:#fff;padding:20px 24px;border:1px solid #e2e8f0;display:table;width:100%;box-sizing:border-box">
<div style="display:table-row">
    <div style="display:table-cell;text-align:center;padding:12px"><div style="font-size:28px;font-weight:700;color:#dc2626">{$critical}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Critical</div></div>
    <div style="display:table-cell;text-align:center;padding:12px"><div style="font-size:28px;font-weight:700;color:#ea580c">{$high}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">High</div></div>
    <div style="display:table-cell;text-align:center;padding:12px"><div style="font-size:28px;font-weight:700;color:#ca8a04">{$medium}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Medium</div></div>
    <div style="display:table-cell;text-align:center;padding:12px"><div style="font-size:28px;font-weight:700;color:#2563eb">{$low}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Low</div></div>
    <div style="display:table-cell;text-align:center;padding:12px"><div style="font-size:28px;font-weight:700;color:#64748b">{$info}</div><div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px">Info</div></div>
</div>
</div>

<!-- Meta -->
<div style="background:#f8fafc;padding:14px 24px;border:1px solid #e2e8f0;border-top:none;font-size:13px;color:#64748b">
    <strong>Frameworks:</strong> {$frameworks} &nbsp;|&nbsp;
    <strong>Date:</strong> {$scan_date}
</div>

<!-- Report Body -->
<div style="background:#fff;padding:30px;border:1px solid #e2e8f0;border-radius:0 0 12px 12px;margin-top:2px">
{$report_html}
</div>

<!-- Footer -->
<div style="text-align:center;padding:20px;color:#94a3b8;font-size:12px">
    Generated by Universal Web Security Scanner v3.0<br>
    Automated report — manual review of flagged items is recommended.
</div>

</div>
</body>
</html>
HTML;

// ── Send Email ──────────────────────────────────────────────────────────────

$subject = "[{$risk_level}] Security Scan: {$hostname} — {$total_issues} issue(s)";

$success = false;
$error_msg = '';

if ($config['smtp_enabled'] && !empty($config['smtp_host'])) {
    $success = send_smtp_email($config, $email, $subject, $email_html, $report, $hostname, $error_msg);
} else {
    // Use PHP mail()
    $boundary = md5(uniqid(time()));

    $headers = implode("\r\n", [
        "From: {$config['from_name']} <{$config['from_email']}>",
        "Reply-To: {$config['from_email']}",
        "MIME-Version: 1.0",
        "Content-Type: multipart/mixed; boundary=\"{$boundary}\"",
        "X-Mailer: SecurityScanReceiver/1.0",
    ]);

    $safe_host = preg_replace('/[^a-zA-Z0-9._-]/', '_', $data['hostname'] ?? 'server');
    $att_name  = "security-report_{$safe_host}_" . date('Y-m-d') . ".md";

    $body  = "--{$boundary}\r\n";
    $body .= "Content-Type: text/html; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($email_html)) . "\r\n";

    $body .= "--{$boundary}\r\n";
    $body .= "Content-Type: text/markdown; charset=UTF-8; name=\"{$att_name}\"\r\n";
    $body .= "Content-Disposition: attachment; filename=\"{$att_name}\"\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($report)) . "\r\n";

    $body .= "--{$boundary}--\r\n";

    $success = @mail($email, $subject, $body, $headers);
    if (!$success) $error_msg = 'PHP mail() returned false. Check server mail config.';
}

if ($success) {
    write_log("Email sent to {$email}");
    respond(200, 'Report received and emailed successfully', [
        'emailed_to'  => $email,
        'risk_level'  => $risk_level,
        'issues'      => $total_issues,
        'saved'       => !empty($saved_file),
    ]);
} else {
    write_log("Email FAILED to {$email}: {$error_msg}", 'ERROR');
    if (!empty($saved_file)) {
        respond(207, 'Report saved locally but email failed', ['error' => $error_msg, 'saved' => true]);
    } else {
        respond(500, 'Email delivery failed', ['error' => $error_msg]);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// BUILT-IN SMTP (no dependencies needed)
// ═══════════════════════════════════════════════════════════════════════════════

function send_smtp_email(array $cfg, string $to, string $subject, string $html, string $md_report, string $host_name, string &$error): bool {
    $timeout = 15;

    try {
        $prefix = ($cfg['smtp_encryption'] === 'ssl') ? "ssl://" : "";
        $socket = @fsockopen("{$prefix}{$cfg['smtp_host']}", $cfg['smtp_port'], $errno, $errstr, $timeout);

        if (!$socket) {
            $error = "Connection failed: {$errstr} ({$errno})";
            return false;
        }

        stream_set_timeout($socket, $timeout);

        $resp = fgets($socket, 512);
        if (substr($resp, 0, 3) !== '220') {
            $error = "Bad greeting: {$resp}";
            fclose($socket);
            return false;
        }

        $local_host = gethostname() ?: 'localhost';

        smtp_send($socket, "EHLO {$local_host}", '250', $error);

        if ($cfg['smtp_encryption'] === 'tls') {
            smtp_send($socket, "STARTTLS", '220', $error);
            $crypto = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $crypto |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }
            if (!stream_socket_enable_crypto($socket, true, $crypto)) {
                $error = "TLS handshake failed";
                fclose($socket);
                return false;
            }
            smtp_send($socket, "EHLO {$local_host}", '250', $error);
        }

        smtp_send($socket, "AUTH LOGIN", '334', $error);
        smtp_send($socket, base64_encode($cfg['smtp_username']), '334', $error);
        smtp_send($socket, base64_encode($cfg['smtp_password']), '235', $error);

        smtp_send($socket, "MAIL FROM:<{$cfg['from_email']}>", '250', $error);
        smtp_send($socket, "RCPT TO:<{$to}>", '250', $error);
        smtp_send($socket, "DATA", '354', $error);

        // Build multipart message
        $boundary  = md5(uniqid(time()));
        $safe_host = preg_replace('/[^a-zA-Z0-9._-]/', '_', $host_name);
        $att_name  = "security-report_{$safe_host}_" . date('Y-m-d') . ".md";

        $msg  = "From: {$cfg['from_name']} <{$cfg['from_email']}>\r\n";
        $msg .= "To: {$to}\r\n";
        $msg .= "Subject: {$subject}\r\n";
        $msg .= "MIME-Version: 1.0\r\n";
        $msg .= "Content-Type: multipart/mixed; boundary=\"{$boundary}\"\r\n\r\n";

        $msg .= "--{$boundary}\r\n";
        $msg .= "Content-Type: text/html; charset=UTF-8\r\n";
        $msg .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $msg .= chunk_split(base64_encode($html));

        $msg .= "--{$boundary}\r\n";
        $msg .= "Content-Type: text/markdown; charset=UTF-8; name=\"{$att_name}\"\r\n";
        $msg .= "Content-Disposition: attachment; filename=\"{$att_name}\"\r\n";
        $msg .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $msg .= chunk_split(base64_encode($md_report));

        $msg .= "--{$boundary}--\r\n";

        // Escape lone dots
        $msg = str_replace("\r\n.", "\r\n..", $msg);

        fwrite($socket, $msg . "\r\n.\r\n");
        $resp = fgets($socket, 512);

        if (substr($resp, 0, 3) !== '250') {
            $error = "Rejected: {$resp}";
            fclose($socket);
            return false;
        }

        smtp_send($socket, "QUIT", '221', $error);
        fclose($socket);
        return true;

    } catch (\Throwable $e) {
        $error = "SMTP exception: " . $e->getMessage();
        if (isset($socket) && is_resource($socket)) fclose($socket);
        return false;
    }
}

function smtp_send($socket, string $cmd, string $expect, string &$error): void {
    fwrite($socket, $cmd . "\r\n");
    $resp = '';
    while ($line = fgets($socket, 512)) {
        $resp .= $line;
        if (isset($line[3]) && $line[3] === ' ') break;
        if (strlen($line) < 4) break;
    }
    if (substr(trim($resp), 0, 3) !== $expect) {
        $error = "SMTP error [{$cmd}]: {$resp}";
    }
}
