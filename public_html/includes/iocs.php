<?php
/**
 * IOC / indicator collection helpers.
 *
 * Two sources:
 *   - live:    current malicious/suspicious state per keyword (tags + VT + abuse.ch);
 *   - reports: the domains that were reported as malicious/suspicious in saved
 *              report snapshots.
 *
 * Formats: plain text (one domain per line, for EDL / MISP freetext) and a MISP
 * event JSON (domain attributes).
 */
require_once __DIR__ . '/db.php';

/** Malicious/suspicious status from a match/report row (same rule as reports). */
function iocStatusFromRow(array $row): string {
    $tag = (string)($row['tag'] ?? '');
    $v = (string)($row['verdict'] ?? '');
    $a = (string)($row['abusech_verdict'] ?? '');
    if ($tag === 'bad' || $v === 'malicious' || $a === 'malicious') {
        return 'malicious';
    }
    if ($v === 'suspicious' || $v === 'dga' || $a === 'suspicious') {
        return 'suspicious';
    }
    return 'clean';
}

/** Whether a status passes the selected severity. */
function iocSeverityMatches(string $status, string $severity): bool {
    if ($status === 'malicious') {
        return true;
    }
    return ($severity === 'malicious_suspicious' && $status === 'suspicious');
}

/** Live indicator rows for the user (optionally one keyword). */
function iocLiveRows(PDO $db, int $userId, ?int $keywordId, string $severity): array {
    $sql = "SELECT m.domain, m.tld, m.first_seen, m.discovered_at,
            k.id AS keyword_id, k.keyword,
            dt.tag, dv.verdict, ab.verdict AS abusech_verdict,
            dw.creation_date
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        LEFT JOIN domain_tags dt ON dt.domain = m.domain
        LEFT JOIN domain_vt dv ON dv.domain = m.domain
        LEFT JOIN domain_abusech ab ON ab.domain = m.domain
        LEFT JOIN domain_whois dw ON dw.domain = m.domain
        WHERE k.user_id = ?
          AND (dt.tag = 'bad'
               OR dv.verdict IN ('malicious','suspicious','dga')
               OR ab.verdict IN ('malicious','suspicious'))";
    $params = [$userId];
    if ($keywordId) {
        $sql .= " AND k.id = ?";
        $params[] = $keywordId;
    }
    $sql .= " ORDER BY k.keyword ASC, m.domain ASC";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $status = iocStatusFromRow($r);
        if (!iocSeverityMatches($status, $severity)) {
            continue;
        }
        $r['status'] = $status;
        $out[] = $r;
    }
    return $out;
}

/** Indicator rows from saved report snapshots (deduplicated, newest report wins). */
function iocReportRows(PDO $db, int $userId, ?int $keywordId, string $severity): array {
    $stmt = $db->prepare("SELECT id, title, group_name, data, created_at
        FROM report_history WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 500");
    $stmt->execute([$userId]);

    $seen = [];
    $out = [];
    foreach ($stmt->fetchAll() as $rec) {
        $json = @gzuncompress((string)$rec['data']);
        if ($json === false) {
            continue;
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            continue;
        }
        $report = is_array($data['report'] ?? null) ? $data['report'] : [];
        foreach ($report as $kwId => $sec) {
            $kwId = (int)$kwId;
            if ($keywordId && $kwId !== $keywordId) {
                continue;
            }
            $kwName = (string)($sec['keyword'] ?? '');
            foreach ((array)($sec['rows'] ?? []) as $row) {
                $domain = strtolower((string)($row['domain'] ?? ''));
                if ($domain === '') {
                    continue;
                }
                $status = iocStatusFromRow($row);
                if (!iocSeverityMatches($status, $severity)) {
                    continue;
                }
                $key = $kwId . '|' . $domain;
                if (isset($seen[$key])) {
                    continue; // a newer report already contributed this pair
                }
                $seen[$key] = true;
                $out[] = [
                    'domain'          => $domain,
                    'tld'             => (string)($row['tld'] ?? ''),
                    'keyword_id'      => $kwId,
                    'keyword'         => $kwName,
                    'tag'             => (string)($row['tag'] ?? ''),
                    'verdict'         => (string)($row['verdict'] ?? ''),
                    'abusech_verdict' => (string)($row['abusech_verdict'] ?? ''),
                    'first_seen'      => $row['first_seen'] ?? null,
                    'discovered_at'   => $row['discovered_at'] ?? null,
                    'creation_date'   => $row['creation_date'] ?? null,
                    'status'          => $status,
                    'report_id'       => (int)$rec['id'],
                ];
            }
        }
    }
    return $out;
}

/** Collect indicator rows for the selected source. */
function iocCollect(PDO $db, int $userId, string $source, ?int $keywordId, string $severity): array {
    if ($source === 'reports') {
        return iocReportRows($db, $userId, $keywordId, $severity);
    }
    return iocLiveRows($db, $userId, $keywordId, $severity);
}

/** Group rows by keyword id (details kept for the table). */
function iocGroupByKeyword(array $rows): array {
    $groups = [];
    foreach ($rows as $r) {
        $kwId = (int)($r['keyword_id'] ?? 0);
        if (!isset($groups[$kwId])) {
            $groups[$kwId] = ['keyword' => (string)($r['keyword'] ?? ''), 'rows' => []];
        }
        $groups[$kwId]['rows'][] = $r;
    }
    uasort($groups, fn($a, $b) => strcasecmp($a['keyword'], $b['keyword']));
    return $groups;
}

/** Ordered unique domains from a row set. */
function iocUniqueDomains(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $d = strtolower((string)($r['domain'] ?? ''));
        if ($d !== '' && !isset($out[$d])) {
            $out[$d] = true;
        }
    }
    return array_keys($out);
}

/** Plain-text list: one domain per line (EDL / MISP freetext). */
function iocFormatTxt(array $rows): string {
    $domains = iocUniqueDomains($rows);
    return $domains ? (implode("\n", $domains) . "\n") : '';
}

/** MISP event JSON with domain attributes. */
function iocFormatMispJson(array $rows, string $scope): string {
    $attrs = [];
    $seen = [];
    foreach ($rows as $r) {
        $d = strtolower((string)($r['domain'] ?? ''));
        if ($d === '' || isset($seen[$d])) {
            continue;
        }
        $seen[$d] = true;
        $comment = trim((string)($r['keyword'] ?? '') . '; ' . (string)($r['status'] ?? ''));
        $attrs[] = [
            'type' => 'domain',
            'category' => 'Network activity',
            'to_ids' => true,
            'distribution' => '0',
            'value' => $d,
            'comment' => $comment,
        ];
    }
    $event = [
        'Event' => [
            'info' => 'ThreatIntelligence-TDL IOCs' . ($scope !== '' ? ' - ' . $scope : ''),
            'distribution' => '0',
            'threat_level_id' => '3',
            'analysis' => '2',
            'Attribute' => $attrs,
        ],
    ];
    return json_encode($event, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
