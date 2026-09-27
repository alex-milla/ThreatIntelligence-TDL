<?php
/**
 * Simple email notification helper
 * Uses PHP mail(). For production SMTP, replace this file with PHPMailer.
 */

/**
 * Domain used for the From: header and links in notification emails.
 *
 * Prefers TDL_MAIL_FROM_DOMAIN so a spoofed Host header can never change the
 * sender; otherwise falls back to the sanitised Host (legacy behaviour).
 */
function mail_from_domain(): string {
    $env = getenv('TDL_MAIL_FROM_DOMAIN');
    if (is_string($env) && $env !== '' && preg_match('/^[A-Za-z0-9.\-]+$/', $env)) {
        return $env;
    }
    return isset($_SERVER['HTTP_HOST'])
        ? preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST'])
        : 'yourdomain.com';
}

function sendMatchEmail(string $to, string $username, array $matches): bool {
    if (empty($matches) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $subject = '[ThreatIntelligence-TDL] New domain matches detected';

    $body = "Hello {$username},\n\n";
    $body .= "The following new domains matching your keywords have been registered:\n\n";
    foreach ($matches as $m) {
        $body .= "- {$m['domain']} (keyword: {$m['keyword']})\n";
    }
    $host = mail_from_domain();
    $body .= "\nView all matches at: https://" . $host . "/\n";
    $body .= "\n--\nThreatIntelligence-TDL";

    $headers = "From: noreply@" . $host . "\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($to, $subject, $body, $headers);
}

/**
 * Email a tracked-domain activation (Intelligence).
 *
 * @param array $items List of ['domain' => ..., 'keyword' => ..., 'reason' => ...].
 */
function sendIntelligenceEmail(string $to, string $username, array $items): bool {
    if (empty($items) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $subject = '[ThreatIntelligence-TDL] Intelligence: tracked domain activation detected';

    $body = "Hello {$username},\n\n";
    $body .= "The following domains under intelligence tracking have shown an activation signal:\n\n";
    foreach ($items as $it) {
        $body .= "- {$it['domain']} (keyword: {$it['keyword']}) - {$it['reason']}\n";
    }
    $host = mail_from_domain();
    $body .= "\nReview them at: https://" . $host . "/intelligence.php\n";
    $body .= "\n--\nThreatIntelligence-TDL";

    $headers = "From: noreply@" . $host . "\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($to, $subject, $body, $headers);
}
