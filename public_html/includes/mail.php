<?php
/**
 * Simple email notification helper
 * Uses PHP mail(). For production SMTP, replace this file with PHPMailer.
 */

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
    $host = isset($_SERVER['HTTP_HOST']) ? preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST']) : 'yourdomain.com';
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
    $host = isset($_SERVER['HTTP_HOST']) ? preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST']) : 'yourdomain.com';
    $body .= "\nReview them at: https://" . $host . "/intelligence.php\n";
    $body .= "\n--\nThreatIntelligence-TDL";

    $headers = "From: noreply@" . $host . "\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    return @mail($to, $subject, $body, $headers);
}
