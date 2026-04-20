<?php
/**
 * Authentication helpers
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
