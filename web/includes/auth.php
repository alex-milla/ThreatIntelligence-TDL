<?php
/**
 * Authentication helpers + CSRF protection
 */

session_start();

function requireAuth(): void {
    if (empty($_SESSION['user_id'])) {
        header('Location: /login.php');
        exit;
    }
}

function requireAdmin(): void {
    requireAuth();
    if (empty($_SESSION['is_admin'])) {
        http_response_code(403);
        exit('Forbidden');
    }
}

function verifyApiKey(PDO $db, string $apiKey): ?array {
    $stmt = $db->prepare("SELECT id, username, is_admin FROM users WHERE api_key = ? AND is_active = 1 LIMIT 1");
    $stmt->execute([$apiKey]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function jsonResponse(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

/* ---------- CSRF Protection ---------- */

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrfField(): void {
    $token = csrfToken();
    echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

function validateCsrf(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }
    $sent   = $_POST['csrf_token'] ?? '';
    $stored = $_SESSION['csrf_token'] ?? '';
    if (!hash_equals($stored, $sent)) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

/* ---------- Security Headers ---------- */

function sendSecurityHeaders(): void {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

/* ---------- Rate Limiting ---------- */

function getClientIp(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        return $_SERVER['HTTP_X_REAL_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function isRateLimited(PDO $db, string $ip, int $maxAttempts = 5, int $windowMinutes = 15): bool {
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at > datetime('now', '-? minutes')");
    $stmt->execute([$ip, $windowMinutes]);
    // SQLite no permite parametrizar intervals directamente en algunas versiones, así que uso string interpolation controlada
    $since = date('Y-m-d H:i:s', strtotime("-{$windowMinutes} minutes"));
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at > ?");
    $stmt->execute([$ip, $since]);
    return (int)$stmt->fetchColumn() >= $maxAttempts;
}

function recordLoginAttempt(PDO $db, string $ip, string $username = ''): void {
    $stmt = $db->prepare("INSERT INTO login_attempts (ip_address, username) VALUES (?, ?)");
    $stmt->execute([$ip, $username]);
}

function clearLoginAttempts(PDO $db, string $ip): void {
    $stmt = $db->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
    $stmt->execute([$ip]);
}

/* ---------- Settings ---------- */

function getSetting(PDO $db, string $key, string $default = ''): string {
    $stmt = $db->prepare("SELECT value FROM settings WHERE key = ? LIMIT 1");
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row ? $row['value'] : $default;
}

function setSetting(PDO $db, string $key, string $value): void {
    $stmt = $db->prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    $stmt->execute([$key, $value]);
}

function isRegistrationOpen(PDO $db): bool {
    return getSetting($db, 'registration_open', '1') === '1';
}
