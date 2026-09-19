<?php
/**
 * RDAP Whois helper with IANA bootstrap caching.
 * Reusable across ajax_whois.php and notifications.php
 */

function getRdapServer(string $tld): ?string {
    $cacheFile = __DIR__ . '/../data/rdap_bootstrap.json';
    $maxAge = 7 * 24 * 3600;

    $bootstrap = null;
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $maxAge) {
        $bootstrap = json_decode(file_get_contents($cacheFile), true);
    }

    if (empty($bootstrap)) {
        $ch = curl_init('https://data.iana.org/rdap/dns.json');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_USERAGENT => 'TDL-Whois/1.0',
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $body = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body && $httpCode === 200) {
            $decoded = json_decode($body, true);
            if (!empty($decoded['services'])) {
                @mkdir(dirname($cacheFile), 0755, true);
                file_put_contents($cacheFile, $body);
                $bootstrap = $decoded;
            }
        }
    }

    if (empty($bootstrap['services'])) {
        return null;
    }

    foreach ($bootstrap['services'] as $service) {
        $tlds = $service[0] ?? [];
        $endpoints = $service[1] ?? [];
        if (in_array($tld, $tlds, true) && !empty($endpoints[0])) {
            return rtrim($endpoints[0], '/') . '/';
        }
    }

    return null;
}

function fetchRdap(string $url, int $timeout = 20): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
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

/**
 * Get whois data for a domain. Returns array with creation_date, expiration_date, registrar.
 * Uses short timeout (3s) when called from bulk contexts like notifications.php.
 */
function getDomainWhois(string $domain, int $timeout = 20): ?array {
    $domain = strtolower(trim($domain));
    if (strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
        return null;
    }

    $parts = explode('.', $domain);
    $tld = end($parts);
    $rdapServer = getRdapServer($tld);
    $rdapUrl = ($rdapServer ?: 'https://rdap.org/') . 'domain/' . urlencode($domain);

    $result = fetchRdap($rdapUrl, $timeout);

    if (!$result['ok'] && $rdapServer) {
        $result = fetchRdap('https://rdap.org/domain/' . urlencode($domain), $timeout);
    }

    if (!$result['ok']) {
        return null;
    }

    $data = $result['data'];
    $creationDate = null;
    $expirationDate = null;
    $registrar = null;

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

    return [
        'creation_date' => $creationDate,
        'expiration_date' => $expirationDate,
        'registrar' => $registrar,
    ];
}
