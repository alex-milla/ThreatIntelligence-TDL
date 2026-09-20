<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$commandId = (int)($_GET['command_id'] ?? 0);
$domain = strtolower(trim($_GET['domain'] ?? ''));
if ($domain !== '' && (strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain))) {
    $domain = '';
}

$response = [
    'success' => true,
    'command_status' => null,
    'command_result' => null,
    'whois' => null,
    'first_seen' => null,
];

if ($commandId) {
    $stmt = $db->prepare("SELECT status, result FROM commands WHERE id = ? LIMIT 1");
    $stmt->execute([$commandId]);
    $cmd = $stmt->fetch();
    if ($cmd) {
        $response['command_status'] = $cmd['status'];
        $response['command_result'] = $cmd['result'];
    }
}

if ($domain !== '') {
    $firstSeen = getDomainFirstSeen($db, $userId, $domain);
    $response['first_seen'] = $firstSeen;

    $stmt = $db->prepare(
        "SELECT domain, creation_date, expiration_date, registrar, name_servers, source, status, updated_at, cached_at "
        . "FROM domain_whois WHERE domain = ? LIMIT 1"
    );
    $stmt->execute([$domain]);
    $row = $stmt->fetch();
    if ($row) {
        $response['whois'] = [
            'domain' => $row['domain'],
            'creation_date' => $row['creation_date'],
            'expiration_date' => $row['expiration_date'],
            'registrar' => $row['registrar'],
            'name_servers' => json_decode($row['name_servers'] ?? '[]', true) ?: [],
            'source' => $row['source'],
            'status' => $row['status'],
            'updated_at' => $row['updated_at'],
            'cached_at' => $row['cached_at'],
            'first_seen' => $firstSeen,
        ];
    }
}

echo json_encode($response);
