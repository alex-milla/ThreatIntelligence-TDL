<?php
/**
 * Shared report data builder.
 *
 * Collects the domains matched by a set of keywords together with their
 * WHOIS/VirusTotal data and computes the per-keyword counters and totals. It is
 * used when a report is generated (and snapshotted into the history) and can
 * also render a live report.
 *
 * Reports include every domain discovered in the selected period, hiding only
 * explicitly excluded domains. Historical (recheck) matches stay hidden unless
 * requested (state = historical or "include archived"). This intentionally
 * differs from the Notifications/Dashboard visibility rules (matchVisibilityClauses).
 */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/report_queue.php';

/**
 * Decorate report rows and compute their counters. Shared by the classic
 * buildReportData() and the manual report queue builder.
 *
 * @return array{0:array<string,int>,1:array} [counts, decorated rows]
 */
function reportDecorateRows(array $rows, int $newDomainDays): array {
    $counts = ['domains' => count($rows), 'new' => 0, 'good' => 0, 'bad' => 0, 'observing' => 0, 'untagged' => 0,
               'malicious' => 0, 'suspicious' => 0, 'dga' => 0, 'clean' => 0, 'watchlist' => 0];

    foreach ($rows as &$r) {
        $tag = (string)($r['tag'] ?? '');
        if (isset($counts[$tag])) {
            $counts[$tag]++;
        } else {
            $counts['untagged']++;
        }

        $verdict = (string)($r['verdict'] ?? '');
        if (isset($counts[$verdict])) {
            $counts[$verdict]++;
        }

        if (!empty($r['in_watchlist'])) {
            $counts['watchlist']++;
        }

        $isNew = false;
        if (!empty($r['creation_date'])) {
            $ts = strtotime((string)$r['creation_date']);
            if ($ts && $ts > strtotime("-{$newDomainDays} days")) {
                $isNew = true;
                $counts['new']++;
            }
        }
        $r['_is_new'] = $isNew;

        $ns = json_decode((string)($r['name_servers'] ?? '[]'), true);
        $r['_ns'] = is_array($ns) ? $ns : [];
    }
    unset($r);

    return [$counts, $rows];
}

/**
 * Build the report data for a set of keywords.
 *
 * @param array $filters ['date'=>'24h','state'=>'all','source'=>'all','archived'=>bool,'group'=>'all']
 * @return array|null Null when the user owns none of the requested keywords.
 */
function buildReportData(PDO $db, int $userId, array $keywordIds, array $filters): ?array {
    $keywordIds = array_values(array_unique(array_filter(array_map('intval', $keywordIds), fn($v) => $v > 0)));
    $keywordIds = array_slice($keywordIds, 0, 50);
    if (empty($keywordIds)) {
        return null;
    }

    // Validate keyword ownership.
    $placeholders = implode(',', array_fill(0, count($keywordIds), '?'));
    $stmt = $db->prepare("SELECT id, keyword FROM keywords WHERE user_id = ? AND id IN ($placeholders) ORDER BY keyword ASC");
    $stmt->execute(array_merge([$userId], $keywordIds));
    $keywords = $stmt->fetchAll();
    if (empty($keywords)) {
        return null;
    }

    // ---------- Filters (whitelisted) ----------
    $validStates = ['all', 'good', 'bad', 'observing', 'untagged', 'watchlist', 'historical'];
    $state = (string)($filters['state'] ?? 'all');
    if (!in_array($state, $validStates, true)) {
        $state = 'all';
    }
    $validSources = ['all', 'czds', 'ct'];
    $source = (string)($filters['source'] ?? 'all');
    if (!in_array($source, $validSources, true)) {
        $source = 'all';
    }
    $validDateFilters = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];
    $date = (string)($filters['date'] ?? '24h');
    if (!array_key_exists($date, $validDateFilters)) {
        $date = '24h';
    }
    $includeArchived = !empty($filters['archived']);

    // Group (header only); only the user's own groups are valid.
    $groupParam = (string)($filters['group'] ?? 'all');
    $groupName = '';
    $groupId = null;
    if (ctype_digit($groupParam)) {
        $gStmt = $db->prepare("SELECT name FROM keyword_groups WHERE id = ? AND user_id = ? LIMIT 1");
        $gStmt->execute([(int)$groupParam, $userId]);
        $found = $gStmt->fetchColumn();
        if ($found !== false) {
            $groupId = (int)$groupParam;
            $groupName = (string)$found;
        }
    } elseif ($groupParam === 'ungrouped') {
        $groupName = 'Ungrouped';
    }

    // ---------- Collect ----------
    $newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
    $maxRows = 2000; // per keyword, to keep reports manageable
    $truncated = false;

    $report = [];
    $totalDomains = 0;
    $grandTag = ['good' => 0, 'bad' => 0, 'observing' => 0, 'untagged' => 0];
    $grandVt = ['malicious' => 0, 'suspicious' => 0, 'dga' => 0, 'clean' => 0];
    $grandNew = 0;
    $grandWatchlist = 0;

    foreach ($keywords as $kw) {
        $kwId = (int)$kw['id'];

        $from = "FROM matches m
            LEFT JOIN domain_tags dt ON dt.domain = m.domain
            LEFT JOIN watchlist w ON w.user_id = ? AND w.domain = m.domain
            LEFT JOIN domain_whois dw ON dw.domain = m.domain
            LEFT JOIN domain_vt dv ON dv.domain = m.domain
            LEFT JOIN domain_abusech ab ON ab.domain = m.domain";

        $where = "WHERE m.keyword_id = ?";
        $params = [$userId, $kwId];

        // Only explicitly excluded domains are hidden; historical unless requested.
        $where .= " AND NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')";
        if (!$includeArchived && $state !== 'historical') {
            $where .= " AND m.is_historical = 0";
        }

        if (in_array($state, ['good', 'bad', 'observing'], true)) {
            $where .= " AND dt.tag = ?";
            $params[] = $state;
        } elseif ($state === 'untagged') {
            $where .= " AND dt.tag IS NULL";
        } elseif ($state === 'watchlist') {
            $where .= " AND w.id IS NOT NULL";
        } elseif ($state === 'historical') {
            $where .= " AND m.is_historical = 1";
        }

        if ($source !== 'all') {
            $where .= " AND m.source = ?";
            $params[] = $source;
        }
        if ($validDateFilters[$date] !== '') {
            $where .= " AND m.discovered_at >= datetime('now', ?)";
            $params[] = $validDateFilters[$date];
        }

        $sql = "SELECT m.domain, m.tld, m.discovered_at, m.first_seen, m.is_historical, m.source,
                dt.tag AS tag, dt.note AS tag_note,
                CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS in_watchlist,
                dw.creation_date, dw.expiration_date, dw.registrar, dw.name_servers, dw.status AS whois_status,
                dw.source AS whois_source, dw.updated_at AS whois_updated_at,
                dv.verdict, dv.malicious, dv.suspicious, dv.harmless, dv.undetected, dv.reputation,
                dv.last_analysis_date, dv.checked_at AS vt_checked_at,
                ab.verdict AS abusech_verdict, ab.urlhaus_verdict AS abusech_urlhaus_verdict,
                ab.urlhaus_url_count AS abusech_urlhaus_url_count, ab.urlhaus_online AS abusech_urlhaus_online,
                ab.urlhaus_dbl AS abusech_urlhaus_dbl, ab.threatfox_verdict AS abusech_threatfox_verdict,
                ab.threatfox_matches AS abusech_threatfox_matches, ab.threat_type AS abusech_threat_type,
                ab.malware_family AS abusech_malware_family, ab.confidence AS abusech_confidence,
                ab.tags AS abusech_tags, ab.last_analysis_date AS abusech_last_analysis_date,
                ab.checked_at AS abusech_checked_at
            $from
            $where
            ORDER BY m.discovered_at DESC, m.domain ASC
            LIMIT " . ($maxRows + 1);

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        if (count($rows) > $maxRows) {
            $rows = array_slice($rows, 0, $maxRows);
            $truncated = true;
        }

        // Keyword without domains in this period is omitted from the report.
        if (empty($rows)) {
            continue;
        }

        [$counts, $rows] = reportDecorateRows($rows, $newDomainDays);

        $report[$kwId] = ['keyword' => $kw['keyword'], 'counts' => $counts, 'rows' => $rows];

        $totalDomains += $counts['domains'];
        $grandNew += $counts['new'];
        $grandWatchlist += $counts['watchlist'];
        foreach ($grandTag as $t => $_) { $grandTag[$t] += $counts[$t]; }
        foreach ($grandVt as $v => $_) { $grandVt[$v] += $counts[$v]; }
    }

    $dateLabels = ['all' => 'All time', '24h' => 'Last 24h', '7d' => 'Last 7 days', '30d' => 'Last 30 days'];
    $stateLabels = ['all' => 'All states', 'good' => 'Good', 'bad' => 'Bad', 'observing' => 'Observing',
                    'untagged' => 'Untagged', 'watchlist' => 'In watchlist', 'historical' => 'Historical'];
    $sourceLabels = ['all' => 'All sources', 'czds' => 'CZDS (zone files)', 'ct' => 'OpenINTEL (CT)'];
    $filterSummary = $dateLabels[$date] . ' · ' . $stateLabels[$state] . ' · ' . $sourceLabels[$source]
        . ($includeArchived ? ' · including tagged/historical/old' : '');

    return [
        'generated_at'   => gmdate('Y-m-d H:i:s'),
        'group_id'       => $groupId,
        'group_name'     => $groupName,
        'filters'        => ['date' => $date, 'state' => $state, 'source' => $source, 'archived' => $includeArchived],
        'filter_summary' => $filterSummary,
        'keywords'       => array_values(array_map(fn($d) => $d['keyword'], $report)),
        'report'         => $report,
        'domains'        => $totalDomains,
        'truncated'      => $truncated,
    ];
}

/**
 * Build a report from the manual report queue (or an explicit domain list).
 *
 * Domain-driven: the analyst decides which domains go to the report, regardless
 * of date/state/source filters. When $groupKey is given, only the keywords that
 * belong to that group are included, and the snapshot carries the group's
 * id/name so History filters it correctly.
 *
 * @param array|null $domains Explicit domains; null = every pending queued domain.
 * @param string|null $groupKey Group id as string, '' for ungrouped, null = no filter.
 * @return array|null Null when there is nothing to report.
 */
function buildReportFromQueue(PDO $db, int $userId, ?array $domains = null, ?string $groupKey = null): ?array {
    if ($domains === null) {
        $domains = reportQueuePendingDomains($db, $userId);
    } else {
        $clean = [];
        foreach ($domains as $d) {
            $d = reportQueueNormalizeDomain((string)$d);
            if ($d !== '') {
                $clean[$d] = true;
            }
        }
        $domains = array_keys($clean);
    }
    $domains = array_slice(array_values(array_unique($domains)), 0, 5000);
    if (empty($domains)) {
        return null;
    }

    // Resolve the group header (when a group filter is applied).
    $groupId = null;
    $groupName = '';
    if ($groupKey !== null && $groupKey !== '' && $groupKey !== 'ungrouped') {
        $gid = (int)$groupKey;
        $gStmt = $db->prepare("SELECT name FROM keyword_groups WHERE id = ? AND user_id = ? LIMIT 1");
        $gStmt->execute([$gid, $userId]);
        $found = $gStmt->fetchColumn();
        if ($found !== false) {
            $groupId = $gid;
            $groupName = (string)$found;
        }
    }

    $newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
    $placeholders = implode(',', array_fill(0, count($domains), '?'));

    // Every match of the user's keywords for the queued domains. A domain that
    // matched several keywords appears under each of them.
    $sql = "SELECT k.id AS keyword_id, k.keyword,
            m.domain, m.tld, m.discovered_at, m.first_seen, m.is_historical, m.source,
            dt.tag AS tag, dt.note AS tag_note,
            CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS in_watchlist,
            dw.creation_date, dw.expiration_date, dw.registrar, dw.name_servers, dw.status AS whois_status,
            dw.source AS whois_source, dw.updated_at AS whois_updated_at,
            dv.verdict, dv.malicious, dv.suspicious, dv.harmless, dv.undetected, dv.reputation,
            dv.last_analysis_date, dv.checked_at AS vt_checked_at,
            ab.verdict AS abusech_verdict, ab.urlhaus_verdict AS abusech_urlhaus_verdict,
            ab.urlhaus_url_count AS abusech_urlhaus_url_count, ab.urlhaus_online AS abusech_urlhaus_online,
            ab.urlhaus_dbl AS abusech_urlhaus_dbl, ab.threatfox_verdict AS abusech_threatfox_verdict,
            ab.threatfox_matches AS abusech_threatfox_matches, ab.threat_type AS abusech_threat_type,
            ab.malware_family AS abusech_malware_family, ab.confidence AS abusech_confidence,
            ab.tags AS abusech_tags, ab.last_analysis_date AS abusech_last_analysis_date,
            ab.checked_at AS abusech_checked_at
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        LEFT JOIN domain_tags dt ON dt.domain = m.domain
        LEFT JOIN watchlist w ON w.user_id = ? AND w.domain = m.domain
        LEFT JOIN domain_whois dw ON dw.domain = m.domain
        LEFT JOIN domain_vt dv ON dv.domain = m.domain
        LEFT JOIN domain_abusech ab ON ab.domain = m.domain
        WHERE k.user_id = ? AND m.domain IN ($placeholders)";
    $params = array_merge([$userId, $userId], $domains);

    if ($groupKey !== null) {
        if ($groupKey === '' || $groupKey === 'ungrouped') {
            $sql .= " AND k.group_id IS NULL";
        } else {
            $sql .= " AND k.group_id = ?";
            $params[] = (int)$groupKey;
        }
    }
    $sql .= " ORDER BY k.keyword ASC, m.discovered_at DESC, m.domain ASC";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $all = $stmt->fetchAll();

    if (empty($all)) {
        return null;
    }

    // Group the joined rows by keyword, preserving query order.
    $byKeyword = [];
    foreach ($all as $row) {
        $kwId = (int)$row['keyword_id'];
        if (!isset($byKeyword[$kwId])) {
            $byKeyword[$kwId] = ['keyword' => $row['keyword'], 'rows' => []];
        }
        unset($row['keyword_id'], $row['keyword']);
        $byKeyword[$kwId]['rows'][] = $row;
    }

    $report = [];
    $totalDomains = 0;
    foreach ($byKeyword as $kwId => $data) {
        [$counts, $rows] = reportDecorateRows($data['rows'], $newDomainDays);
        $report[$kwId] = ['keyword' => $data['keyword'], 'counts' => $counts, 'rows' => $rows];
        $totalDomains += $counts['domains'];
    }

    if ($groupKey === null) {
        $scope = '';
    } elseif ($groupName !== '') {
        $scope = 'Group "' . $groupName . '" · ';
    } else {
        $scope = 'Ungrouped · ';
    }

    return [
        'generated_at'   => gmdate('Y-m-d H:i:s'),
        'group_id'       => $groupId,
        'group_name'     => $groupName,
        'filters'        => ['mode' => 'queue', 'group' => $groupKey, 'date' => 'all', 'state' => 'all', 'source' => 'all', 'archived' => true],
        'filter_summary' => 'Manual report queue · ' . $scope . $totalDomains . ' domain(s)',
        'keywords'       => array_values(array_map(fn($d) => $d['keyword'], $report)),
        'report'         => $report,
        'domains'        => $totalDomains,
        'truncated'      => false,
    ];
}
