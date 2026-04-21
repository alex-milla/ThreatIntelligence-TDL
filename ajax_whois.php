<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');

session_start();
if (empty($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$domain = trim($_GET['domain'] ?? '');
if (!$domain || strlen($domain) > 253 || !preg_match('/^[a-z0-9\-\.]+$/', $domain)) {
    echo json_encode(['success' => false, 'error' => 'Invalid domain']);
    exit;
}

$rdapUrl = 'https://rdap.org/domain/' . urlencode(strtolower($domain));

$ctx = stream_context_create([
    'http' => [
        'timeout' => 15,
        'user_agent' => 'TDL-Whois/1.0',
    ],
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
    ],
]);

$response = @file_get_contents($rdapUrl, false, $ctx);
if ($response === false) {
    echo json_encode(['success' => false, 'error' => 'RDAP query failed']);
    exit;
}

$data = json_decode($response, true);
if (!$data) {
    echo json_encode(['success' => false, 'error' => 'Invalid RDAP response']);
    exit;
}

// Extract useful fields
$creationDate = null;
$expirationDate = null;
$registrar = null;
$nameServers = [];

if (!empty($data['events'])) {
    foreach ($data['events'] as $event) {
        $action = strtolower($event['eventAction'] ?? '');
        if (strpos($action, 'registration') !== false && empty($creationDate)) {
            $creationDate = $event['eventDate'] ?? null;
        }
        if ((strpos($action, 'expiration') !== false || strpos($action, 'renewal') !== false) && empty($expirationDate)) {
            $expirationDate = $event['eventDate'] ?? null;
        }
    }
}

if (!empty($data['entities'])) {
    foreach ($data['entities'] as $entity) {
        $roles = array_map('strtolower', $entity['roles'] ?? []);
        if (in_array('registrar', $roles)) {
            if (!empty($entity['vcardArray'][1])) {
                foreach ($entity['vcardArray'][1] as $vcard) {
                    if (($vcard[0] ?? '') === 'fn' || ($vcard[0] ?? '') === 'organization') {
                        $registrar = $vcard[3] ?? null;
                        break 2;
                    }
                }
            }
            if (empty($registrar) && !empty($entity['publicIds'])) {
                foreach ($entity['publicIds'] as $pid) {
                    if (($pid['type'] ?? '') === 'IANA Registrar ID') {
                        $registrar = 'Registrar ID ' . ($pid['identifier'] ?? '?');
                        break 2;
                    }
                }
            }
        }
    }
}

if (!empty($data['nameservers'])) {
    foreach ($data['nameservers'] as $ns) {
        $nameServers[] = $ns['ldhName'] ?? null;
    }
}

echo json_encode([
    'success' => true,
    'domain' => $domain,
    'creationDate' => $creationDate,
    'expirationDate' => $expirationDate,
    'registrar' => $registrar,
    'nameServers' => array_filter($nameServers),
    'raw' => $data,
]);
