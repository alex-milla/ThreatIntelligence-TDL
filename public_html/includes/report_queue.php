<?php
/**
 * Manual report queue.
 *
 * The analyst reviews domains (keyword match lists / notifications), validates
 * WHOIS + VirusTotal and marks the ones to include in the next report.
 *
 * The queue is keyed per (user, domain, group): a domain that matches keywords
 * in several groups is queued once per group, so every report is assigned to
 * the keyword group it belongs to. Pending entries accumulate until a report is
 * generated for their group; generating a group's report consumes only that
 * group's entries.
 */
require_once __DIR__ . '/db.php';

/** Normalise a domain for queue storage/lookup. */
function reportQueueNormalizeDomain(string $domain): string {
    return strtolower(trim($domain));
}

/** Normalise a group key: a group id as string, or '' for ungrouped. */
function reportQueueNormalizeGroupKey($groupKey): string {
    if ($groupKey === null || $groupKey === '' || $groupKey === 'ungrouped') {
        return '';
    }
    return ctype_digit((string)$groupKey) ? (string)(int)$groupKey : '';
}

/**
 * Group keys ('' or group id) that each domain belongs to, from the user's
 * matched keywords. Domains with no match for this user are absent from the map.
 *
 * @return array<string,array<string>> domain => list of group keys
 */
function reportQueueDomainGroups(PDO $db, int $userId, array $domains): array {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("SELECT DISTINCT m.domain, COALESCE(CAST(k.group_id AS TEXT), '') AS gk
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain IN ($placeholders)");
    $stmt->execute(array_merge([$userId], $clean));
    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $out[strtolower($row['domain'])][(string)$row['gk']] = true;
    }
    $result = [];
    foreach ($out as $domain => $keys) {
        $result[$domain] = array_keys($keys);
    }
    return $result;
}

/**
 * Add (or re-add) domains to the user's report queue, one entry per keyword
 * group. Returns the number of rows queued. Re-queueing a previously reported
 * entry resets it to pending. Domains that do not match any of the user's
 * keywords are ignored.
 */
function reportQueueAdd(PDO $db, int $userId, array $domains, ?string $groupKey = null): int {
    $groups = reportQueueDomainGroups($db, $userId, $domains);
    if (empty($groups)) {
        return 0;
    }

    // Explicit group (from the "send to report" selector): move the domains to
    // that single group, dropping any previous pending entry so they are not
    // queued twice.
    if ($groupKey !== null) {
        $gk = reportQueueNormalizeGroupKey($groupKey);
        if ($gk !== '') {
            $chk = $db->prepare("SELECT COUNT(*) FROM keyword_groups WHERE id = ? AND user_id = ?");
            $chk->execute([(int)$gk, $userId]);
            if (!(int)$chk->fetchColumn()) {
                $gk = '';
            }
        }
        $valid = array_keys($groups);
        $placeholders = implode(',', array_fill(0, count($valid), '?'));
        $db->prepare("DELETE FROM report_queue WHERE user_id = ? AND reported_at IS NULL AND domain IN ($placeholders)")
           ->execute(array_merge([$userId], $valid));
        $stmt = $db->prepare("INSERT OR REPLACE INTO report_queue
            (user_id, domain, group_key, added_at, reported_at, report_id)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL)");
        $count = 0;
        foreach ($valid as $domain) {
            $stmt->execute([$userId, $domain, $gk]);
            $count++;
        }
        return $count;
    }

    // Auto: assign the domain to every group of its matched keywords.
    $stmt = $db->prepare("INSERT OR REPLACE INTO report_queue
        (user_id, domain, group_key, added_at, reported_at, report_id)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL)");
    $count = 0;
    foreach ($groups as $domain => $keys) {
        if (empty($keys)) {
            $keys = [''];
        }
        foreach ($keys as $gk) {
            $stmt->execute([$userId, $domain, (string)$gk]);
            $count++;
        }
    }
    return $count;
}

/**
 * Remove domains from the user's report queue. When $groupKey is null, every
 * entry for the domains is removed; otherwise only the entries of that group.
 * Returns the number of rows deleted.
 */
function reportQueueRemove(PDO $db, int $userId, array $domains, ?string $groupKey = null): int {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return 0;
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    if ($groupKey === null) {
        $stmt = $db->prepare("DELETE FROM report_queue WHERE user_id = ? AND domain IN ($placeholders)");
        $stmt->execute(array_merge([$userId], $clean));
    } else {
        $stmt = $db->prepare("DELETE FROM report_queue WHERE user_id = ? AND group_key = ? AND domain IN ($placeholders)");
        $stmt->execute(array_merge([$userId, reportQueueNormalizeGroupKey($groupKey)], $clean));
    }
    return $stmt->rowCount();
}

/** Number of distinct domains with at least one pending entry. */
function reportQueuePendingCount(PDO $db, int $userId): int {
    $stmt = $db->prepare("SELECT COUNT(DISTINCT domain) FROM report_queue WHERE user_id = ? AND reported_at IS NULL");
    $stmt->execute([$userId]);
    return (int)$stmt->fetchColumn();
}

/**
 * Pending queue rows, one per (domain, group), with the keywords of the user's
 * that matched the domain inside that group.
 *
 * @return array<int,array{domain:string,group_key:string,group_id:?int,group_name:string,keywords:array<int,string>,added_at:?string}>
 */
function reportQueuePendingRows(PDO $db, int $userId, int $limit = 5000): array {
    $stmt = $db->prepare("SELECT domain, group_key, added_at
        FROM report_queue
        WHERE user_id = ? AND reported_at IS NULL
        ORDER BY group_key ASC, added_at ASC, domain ASC
        LIMIT " . (int)$limit);
    $stmt->execute([$userId]);
    $rows = $stmt->fetchAll();
    if (empty($rows)) {
        return [];
    }

    $domains = array_values(array_unique(array_column($rows, 'domain')));
    $placeholders = implode(',', array_fill(0, count($domains), '?'));

    // Keyword labels per domain. A report group does not restrict which of the
    // domain's keywords are shown, so a domain sent to another group is not blank.
    $kwStmt = $db->prepare("SELECT DISTINCT m.domain, k.keyword
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain IN ($placeholders)
        ORDER BY k.keyword ASC");
    $kwStmt->execute(array_merge([$userId], $domains));
    $kwMap = [];
    foreach ($kwStmt->fetchAll() as $r) {
        $kwMap[strtolower($r['domain'])][] = $r['keyword'];
    }

    // Group names.
    $gStmt = $db->prepare("SELECT id, name FROM keyword_groups WHERE user_id = ?");
    $gStmt->execute([$userId]);
    $names = [];
    foreach ($gStmt->fetchAll() as $g) {
        $names[(string)(int)$g['id']] = (string)$g['name'];
    }

    $out = [];
    foreach ($rows as $r) {
        $domain = strtolower($r['domain']);
        $gk = (string)$r['group_key'];
        $out[] = [
            'domain'     => $domain,
            'group_key'  => $gk,
            'group_id'   => ($gk !== '' && ctype_digit($gk)) ? (int)$gk : null,
            'group_name' => ($gk !== '' && isset($names[$gk])) ? $names[$gk] : '',
            'keywords'   => $kwMap[$domain] ?? [],
            'added_at'   => $r['added_at'],
        ];
    }
    return $out;
}

/**
 * Pending rows grouped by group key (for the Queue tab buckets/counters).
 *
 * @return array<string,array{group_key:string,group_id:?int,group_name:string,domains:array<int,string>,keywords:array<int,string>,count:int}>
 */
function reportQueuePendingByGroup(PDO $db, int $userId): array {
    $buckets = [];
    foreach (reportQueuePendingRows($db, $userId) as $row) {
        $gk = $row['group_key'];
        if (!isset($buckets[$gk])) {
            $buckets[$gk] = [
                'group_key'  => $gk,
                'group_id'   => $row['group_id'],
                'group_name' => $row['group_name'],
                'domains'    => [],
                'keywords'   => [],
                'count'      => 0,
            ];
        }
        $buckets[$gk]['domains'][] = $row['domain'];
        $buckets[$gk]['count']++;
        foreach ($row['keywords'] as $kw) {
            if (!in_array($kw, $buckets[$gk]['keywords'], true)) {
                $buckets[$gk]['keywords'][] = $kw;
            }
        }
    }
    return $buckets;
}

/** Distinct domains currently pending for the user (lowercased list). */
function reportQueuePendingDomains(PDO $db, int $userId): array {
    $stmt = $db->prepare("SELECT DISTINCT domain FROM report_queue WHERE user_id = ? AND reported_at IS NULL ORDER BY added_at ASC");
    $stmt->execute([$userId]);
    return array_map('strtolower', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

/**
 * Queue status for a set of domains (used to paint the "Queued" badges).
 * A domain is pending when it has at least one unreported entry.
 *
 * @return array<string,array{added_at:?string,reported_at:?string,groups:array<int,string>}>
 */
function reportQueueStatus(PDO $db, int $userId, array $domains): array {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("SELECT domain, group_key, added_at, reported_at
        FROM report_queue WHERE user_id = ? AND domain IN ($placeholders)
        ORDER BY added_at ASC");
    $stmt->execute(array_merge([$userId], $clean));
    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $domain = strtolower($row['domain']);
        if (!isset($out[$domain])) {
            $out[$domain] = ['added_at' => $row['added_at'], 'reported_at' => $row['reported_at'], 'groups' => []];
        }
        $out[$domain]['groups'][] = (string)$row['group_key'];
        // Pending if any entry is still unreported.
        if ($row['reported_at'] === null) {
            $out[$domain]['reported_at'] = null;
        }
        if ($row['added_at'] !== null && ($out[$domain]['added_at'] === null || $row['added_at'] < $out[$domain]['added_at'])) {
            $out[$domain]['added_at'] = $row['added_at'];
        }
    }
    return $out;
}

/**
 * Stamp pending entries as reported by a generated report. When $groupKey is
 * null, every pending entry of the user is stamped; otherwise only the entries
 * of that group. `$domains` limits the update to those domains (null = all).
 */
function reportQueueMarkReported(PDO $db, int $userId, int $reportId, ?string $groupKey = null, ?array $domains = null): int {
    $now = gmdate('Y-m-d H:i:s');
    $sql = "UPDATE report_queue SET reported_at = ?, report_id = ? WHERE user_id = ? AND reported_at IS NULL";
    $params = [$now, $reportId, $userId];

    if ($groupKey !== null) {
        $sql .= " AND group_key = ?";
        $params[] = reportQueueNormalizeGroupKey($groupKey);
    }

    if ($domains !== null) {
        $clean = [];
        foreach ($domains as $d) {
            $d = reportQueueNormalizeDomain((string)$d);
            if ($d !== '') {
                $clean[$d] = true;
            }
        }
        $clean = array_keys($clean);
        if (empty($clean)) {
            return 0;
        }
        $placeholders = implode(',', array_fill(0, count($clean), '?'));
        $sql .= " AND domain IN ($placeholders)";
        $params = array_merge($params, $clean);
    }

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    return $stmt->rowCount();
}
