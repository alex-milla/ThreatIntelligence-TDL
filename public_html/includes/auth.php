<?php
/**
 * Authentication helpers + CSRF protection
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ---------- Date formatting (UTC → local) ---------- */

/**
 * Convert a UTC timestamp (ISO 8601 or SQLite format) to Europe/Madrid local time.
 * All timestamps in the DB are stored in UTC; this helper is used for display.
 */
function fmt_date(?string $utc): string {
    if (!$utc || $utc === '' || $utc === '0000-00-00 00:00:00') {
        return '—';
    }
    static $tzLocal = null;
    static $tzUtc = null;
    if ($tzLocal === null) {
        $tzUtc = new DateTimeZone('UTC');
        $tzLocal = new DateTimeZone('Europe/Madrid');
    }
    try {
        $dt = new DateTime($utc, $tzUtc);
        $dt->setTimezone($tzLocal);
        return $dt->format('Y-m-d H:i:s');
    } catch (Throwable $e) {
        return $utc;
    }
}

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
    $sent   = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    $stored = $_SESSION['csrf_token'] ?? '';
    if (!hash_equals($stored, $sent)) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

/* ---------- Security Headers ---------- */

function sendSecurityHeaders(): void {
    if (headers_sent()) {
        return;
    }
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
    // Compatible con SQLite antiguo (pre-3.24) que no soporta ON CONFLICT DO UPDATE
    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
    $stmt->execute([$key, $value]);
}

function isRegistrationOpen(PDO $db): bool {
    return getSetting($db, 'registration_open', '1') === '1';
}

function hasPendingCommand(PDO $db, string $command): bool {
    $stmt = $db->prepare("SELECT COUNT(*) FROM commands WHERE command = ? AND status IN ('pending','running')");
    $stmt->execute([$command]);
    return (int)$stmt->fetchColumn() > 0;
}

/**
 * Summarise whether the worker, a recheck or any queued command is active.
 *
 * The web UI polls this so it can refresh itself once the background work
 * finishes instead of leaving the page stale until a manual reload. The data
 * is not sensitive (only activity flags and the worker version).
 */
function getWorkerActivity(PDO $db): array {
    $activity = [
        'active'           => false,
        'worker_running'   => false,
        'recheck_running'  => false,
        'commands_pending' => 0,
        'commands_running' => 0,
        'max_command_id'   => 0,
        'worker_version'   => '',
        'last_run'         => null,
    ];

    try {
        $ws = $db->query("SELECT is_running, version, last_run FROM worker_status WHERE id = 1")->fetch();
        if ($ws) {
            $activity['worker_running'] = !empty($ws['is_running']);
            $activity['worker_version'] = (string)($ws['version'] ?? '');
            $activity['last_run'] = $ws['last_run'] ?? null;
        }
    } catch (Throwable $e) {
        // Table not created yet.
    }

    try {
        $rc = $db->query("SELECT is_running FROM recheck_status WHERE id = 1")->fetch();
        if ($rc) {
            $activity['recheck_running'] = !empty($rc['is_running']);
        }
    } catch (Throwable $e) {
        // Table not created yet.
    }

    try {
        $row = $db->query(
            "SELECT "
            . "SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS p, "
            . "SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS r, "
            . "COALESCE(MAX(id), 0) AS m FROM commands"
        )->fetch();
        if ($row) {
            $activity['commands_pending'] = (int)($row['p'] ?? 0);
            $activity['commands_running'] = (int)($row['r'] ?? 0);
            $activity['max_command_id'] = (int)($row['m'] ?? 0);
        }
    } catch (Throwable $e) {
        // Table not created yet.
    }

    $activity['active'] = $activity['worker_running']
        || $activity['recheck_running']
        || $activity['commands_pending'] > 0
        || $activity['commands_running'] > 0;

    return $activity;
}

/**
 * Return ['app' => x, 'worker' => y] when the running worker reports a version
 * different from the application VERSION file, or null if they match/unknown.
 */
function workerVersionMismatch(PDO $db): ?array {
    $versionFile = dirname(__DIR__) . '/VERSION';
    $app = is_file($versionFile) ? trim(file_get_contents($versionFile)) : '';
    $worker = '';
    try {
        $worker = (string)$db->query("SELECT version FROM worker_status WHERE id = 1")->fetchColumn();
    } catch (Throwable $e) {
        $worker = '';
    }
    if ($app === '' || $worker === '' || $worker === 'unknown' || $worker === $app) {
        return null;
    }
    return ['app' => $app, 'worker' => $worker];
}

function getMaxKeywords(PDO $db, int $userId): int {
    $stmt = $db->prepare("SELECT max_keywords FROM users WHERE id = ? LIMIT 1");
    $stmt->execute([$userId]);
    $val = $stmt->fetchColumn();
    return $val !== false ? (int)$val : 10;
}

function canAddKeyword(PDO $db, int $userId): bool {
    $limit = getMaxKeywords($db, $userId);
    if ($limit === 0) {
        return true; // 0 means unlimited
    }
    $stmt = $db->prepare("SELECT COUNT(*) FROM keywords WHERE user_id = ? AND is_active = 1");
    $stmt->execute([$userId]);
    $current = (int)$stmt->fetchColumn();
    return $current < $limit;
}

/* ---------- API Rate Limiting ---------- */

function checkApiRateLimit(PDO $db, string $ip, string $apiKey = '', string $endpoint = ''): bool {
    $windowSeconds = 60;

    // Check if key belongs to admin -> higher limit
    $isAdmin = false;
    if ($apiKey) {
        $stmt = $db->prepare("SELECT is_admin FROM users WHERE api_key = ? LIMIT 1");
        $stmt->execute([$apiKey]);
        $isAdmin = (bool)$stmt->fetchColumn();
    }

    $maxRequests = $isAdmin ? 600 : ($apiKey ? 120 : 10);

    $since = date('Y-m-d H:i:s', strtotime("-{$windowSeconds} seconds"));

    // Deterministic cleanup to prevent table bloat
    try {
        $db->prepare("DELETE FROM api_requests WHERE requested_at < ?")->execute([$since]);
    } catch (Throwable $e) {
        // ignore cleanup errors
    }

    // Check IP-based limit
    $stmt = $db->prepare("SELECT COUNT(*) FROM api_requests WHERE ip_address = ? AND requested_at > ?");
    $stmt->execute([$ip, $since]);
    if ((int)$stmt->fetchColumn() >= $maxRequests) {
        return true;
    }

    // Log this request
    $stmt = $db->prepare("INSERT INTO api_requests (ip_address, api_key, endpoint, requested_at) VALUES (?, ?, ?, datetime('now'))");
    $stmt->execute([$ip, $apiKey, $endpoint]);

    return false;
}
