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
