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

function fetchRdap(string $url): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT => 'TDL-Whois/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'error' => 'cURL error: ' . $err];
    }
    if ($httpCode !== 200) {
        return ['ok' => false, 'error' => 'HTTP ' . $httpCode];
    }

    $data = json_decode($body, true);
    if (!$data) {
        return ['ok' => false, 'error' => 'Invalid JSON response'];
    }
    return ['ok' => true, 'data' => $data];
}

$result = fetchRdap($rdapUrl);

if (!$result['ok']) {
    // Fallback: try TLD-specific RDAP bootstrap
    $parts = explode('.', strtolower($domain));
    $tld = end($parts);
    $fallbackUrl = "https://rdap.org/domain/" . urlencode(strtolower($domain));
    // No real fallback needed, rdap.org handles all TLDs via redirect
    echo json_encode([
        'success' => false,
        'error' => $result['error'],
        'fallback_url' => 'https://who.is/whois/' . urlencode(strtolower($domain)),
    ]);
    exit;
}

$data = $result['data'];

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
]);
