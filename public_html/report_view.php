<?php
/**
 * Printable report.
 *
 * Renders the domains matched by the selected keywords, grouped by keyword,
 * with all the data collected for each domain (WHOIS, VirusTotal, tags,
 * watchlist, first seen, source...). Sections for keywords with no matching
 * domains are omitted, so a report only contains the keywords from the last
 * sync. Designed to be printed (browser "Print / Save as PDF"): sections break
 * per keyword and interactive controls are hidden by the print stylesheet.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

// ---------- Selected keywords ----------
$idsParam = (string)($_GET['keywords'] ?? '');
$ids = array_values(array_unique(array_filter(array_map('intval', explode(',', $idsParam)), fn($v) => $v > 0)));
$ids = array_slice($ids, 0, 50);

// ---------- Filters (whitelisted) ----------
$validStates = ['all', 'good', 'bad', 'observing', 'untagged', 'watchlist', 'historical'];
$state = (string)($_GET['state'] ?? 'all');
if (!in_array($state, $validStates, true)) {
    $state = 'all';
}
$validSources = ['all', 'czds', 'ct'];
$source = (string)($_GET['source'] ?? 'all');
if (!in_array($source, $validSources, true)) {
    $source = 'all';
}
$validDateFilters = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];
$date = (string)($_GET['date'] ?? '24h');
if (!array_key_exists($date, $validDateFilters)) {
    $date = '24h';
}
$includeArchived = isset($_GET['archived']) && $_GET['archived'] === '1';

// ---------- Optional group (for the report header) ----------
$groupParam = (string)($_GET['group'] ?? 'all');
$groupName = '';
if (ctype_digit($groupParam)) {
    $gStmt = $db->prepare("SELECT name FROM keyword_groups WHERE id = ? AND user_id = ? LIMIT 1");
    $gStmt->execute([(int)$groupParam, $userId]);
    $groupName = (string)($gStmt->fetchColumn() ?: '');
} elseif ($groupParam === 'ungrouped') {
    $groupName = 'Ungrouped';
}

// ---------- Validate keyword ownership ----------
$keywords = [];
if (!empty($ids)) {
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $db->prepare("SELECT id, keyword FROM keywords WHERE user_id = ? AND id IN ($placeholders) ORDER BY keyword ASC");
    $stmt->execute(array_merge([$userId], $ids));
    $keywords = $stmt->fetchAll();
}

$pageTitle = 'Report';
require __DIR__ . '/templates/header.php';

if (empty($keywords)) {
    ?>
    <div class="card">
        <div class="card-head"><h2>No keywords selected</h2></div>
        <p class="muted">Pick at least one keyword to generate a report.</p>
        <a href="/reports.php" class="btn waves-effect"><i class="material-icons left">arrow_back</i>Back to Reports</a>
    </div>
    <?php
    require __DIR__ . '/templates/footer.php';
    exit;
}

// ---------- Collect the data ----------
$newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
$maxRows = 2000; // per keyword, to keep printing manageable
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
        LEFT JOIN domain_vt dv ON dv.domain = m.domain";

    $where = "WHERE m.keyword_id = ?";
    $params = [$userId, $kwId];

    // Reports include every domain discovered in the period; only explicitly
    // excluded domains are hidden. Historical (recheck) matches are hidden
    // unless the user asks for them (state = historical or "include archived").
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
            dt.tag AS tag,
            CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS in_watchlist,
            dw.creation_date, dw.expiration_date, dw.registrar, dw.name_servers, dw.status AS whois_status,
            dv.verdict, dv.malicious, dv.suspicious, dv.harmless, dv.undetected, dv.reputation, dv.last_analysis_date
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

    // Keywords without domains in this period are omitted from the report.
    if (empty($rows)) {
        continue;
    }

    // Per-keyword counters
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

    $report[$kwId] = ['keyword' => $kw['keyword'], 'counts' => $counts, 'rows' => $rows];

    $totalDomains += $counts['domains'];
    $grandNew += $counts['new'];
    $grandWatchlist += $counts['watchlist'];
    foreach ($grandTag as $t => $_) { $grandTag[$t] += $counts[$t]; }
    foreach ($grandVt as $v => $_) { $grandVt[$v] += $counts[$v]; }
}

$includedKeywords = array_values(array_map(fn($d) => $d['keyword'], $report));

// Human-readable filter summary
$dateLabels = ['all' => 'All time', '24h' => 'Last 24h', '7d' => 'Last 7 days', '30d' => 'Last 30 days'];
$stateLabels = ['all' => 'All states', 'good' => 'Good', 'bad' => 'Bad', 'observing' => 'Observing',
                'untagged' => 'Untagged', 'watchlist' => 'In watchlist', 'historical' => 'Historical'];
$sourceLabels = ['all' => 'All sources', 'czds' => 'CZDS (zone files)', 'ct' => 'OpenINTEL (CT)'];
$filterSummary = $dateLabels[$date] . ' · ' . $stateLabels[$state] . ' · ' . $sourceLabels[$source]
    . ($includeArchived ? ' · including tagged/historical/old' : '');

$generatedAt = fmt_date(gmdate('Y-m-d H:i:s'));
$vtLabels = ['malicious' => 'MALICIOUS', 'dga' => 'DGA', 'suspicious' => 'SUSPICIOUS', 'clean' => 'CLEAN'];
$tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];

// Small helper: render the cached VirusTotal cell (verdict + engine counts).
function reportVtCell(array $r, array $vtLabels): string {
    if ($r['verdict'] === null) {
        return '<span class="muted">Not checked</span>';
    }
    $val = (string)$r['verdict'];
    $badge = isset($vtLabels[$val])
        ? '<span class="vt-badge vt-' . $val . '">' . $vtLabels[$val] . '</span>'
        : '<span class="muted">' . htmlspecialchars($val) . '</span>';
    $detail = sprintf('M %d · S %d · H %d · U %d',
        (int)$r['malicious'], (int)$r['suspicious'], (int)$r['harmless'], (int)$r['undetected']);
    if ((int)$r['reputation'] !== 0) {
        $detail .= ' · rep ' . (int)$r['reputation'];
    }
    return '<div class="vt-cell">' . $badge . '<span class="vt-detail">' . htmlspecialchars($detail) . '</span></div>';
}
?>

<div class="report-toolbar no-print">
    <a href="/reports.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">arrow_back</i>Back to Reports</a>
    <button type="button" class="btn btn-small waves-effect" onclick="window.print()"><i class="material-icons left">print</i>Print / Save as PDF</button>
</div>

<div class="card report-card">
    <header class="report-cover">
        <div class="report-cover-brand">ThreatIntelligence-TDL</div>
        <h1>Domain Threat Report</h1>
        <div class="report-cover-sub">
            <?php if ($groupName !== ''): ?><span>Group: <strong><?= htmlspecialchars($groupName) ?></strong></span><?php endif; ?>
            <span>Period: <strong><?= htmlspecialchars($dateLabels[$date]) ?></strong></span>
            <span>Generated: <strong><?= htmlspecialchars($generatedAt) ?></strong> (Europe/Madrid)</span>
            <span>User: <strong><?= htmlspecialchars($_SESSION['username'] ?? '') ?></strong></span>
        </div>
    </header>

    <?php if (empty($report)): ?>
        <p class="muted">No domains matched the current filters for the selected keywords. Widen the period or include tagged/historical domains.</p>
    <?php else: ?>

    <section class="report-kpis">
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($totalDomains) ?></span><span class="report-kpi-label">Domains</span></div>
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($grandNew) ?></span><span class="report-kpi-label">New</span></div>
        <div class="report-kpi danger"><span class="report-kpi-value"><?= number_format($grandVt['malicious']) ?></span><span class="report-kpi-label">Malicious</span></div>
        <div class="report-kpi warning"><span class="report-kpi-value"><?= number_format($grandVt['suspicious']) ?></span><span class="report-kpi-label">Suspicious</span></div>
        <div class="report-kpi good"><span class="report-kpi-value"><?= number_format($grandTag['good']) ?></span><span class="report-kpi-label">Good</span></div>
        <div class="report-kpi bad"><span class="report-kpi-value"><?= number_format($grandTag['bad']) ?></span><span class="report-kpi-label">Bad</span></div>
    </section>

    <div class="report-meta">
        <div><span class="report-meta-label">Keywords included</span> <?= count($report) ?></div>
        <div><span class="report-meta-label">Domains</span> <?= number_format($totalDomains) ?></div>
        <div><span class="report-meta-label">Filters</span> <?= htmlspecialchars($filterSummary) ?></div>
    </div>
    <div class="report-keywords">
        <?php foreach ($includedKeywords as $name): ?>
            <span class="report-keyword-chip"><?= htmlspecialchars($name) ?></span>
        <?php endforeach; ?>
    </div>

    <h2 class="report-section-title">Summary</h2>
    <table class="striped report-table report-summary">
        <thead>
            <tr>
                <th>Keyword</th>
                <th class="num">Domains</th>
                <th class="num">New</th>
                <th class="num">Good</th>
                <th class="num">Bad</th>
                <th class="num">Observing</th>
                <th class="num">Untagged</th>
                <th class="num">Watchlist</th>
                <th class="num">Malicious</th>
                <th class="num">Suspicious</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($report as $data): $c = $data['counts']; ?>
            <tr>
                <td><strong><?= htmlspecialchars($data['keyword']) ?></strong></td>
                <td class="num"><?= number_format($c['domains']) ?></td>
                <td class="num"><?= number_format($c['new']) ?></td>
                <td class="num"><?= number_format($c['good']) ?></td>
                <td class="num"><?= number_format($c['bad']) ?></td>
                <td class="num"><?= number_format($c['observing']) ?></td>
                <td class="num"><?= number_format($c['untagged']) ?></td>
                <td class="num"><?= number_format($c['watchlist']) ?></td>
                <td class="num"><?= number_format($c['malicious']) ?></td>
                <td class="num"><?= number_format($c['suspicious']) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr>
                <th>Total</th>
                <th class="num"><?= number_format($totalDomains) ?></th>
                <th class="num"><?= number_format($grandNew) ?></th>
                <th class="num"><?= number_format($grandTag['good']) ?></th>
                <th class="num"><?= number_format($grandTag['bad']) ?></th>
                <th class="num"><?= number_format($grandTag['observing']) ?></th>
                <th class="num"><?= number_format($grandTag['untagged']) ?></th>
                <th class="num"><?= number_format($grandWatchlist) ?></th>
                <th class="num"><?= number_format($grandVt['malicious']) ?></th>
                <th class="num"><?= number_format($grandVt['suspicious']) ?></th>
            </tr>
        </tfoot>
    </table>

    <?php if ($truncated): ?>
        <p class="muted no-print">Some keyword sections were truncated to <?= number_format($maxRows) ?> domains each. Narrow the filters to print everything.</p>
    <?php endif; ?>

    <?php foreach ($report as $data): $c = $data['counts']; ?>
        <section class="report-section">
            <h2 class="report-section-title report-keyword-title">
                <span class="report-keyword-name"><?= htmlspecialchars($data['keyword']) ?></span>
                <span class="report-keyword-stats">
                    <span class="report-pill"><?= number_format($c['domains']) ?> domains</span>
                    <?php if ($c['new'] > 0): ?><span class="report-pill new"><?= number_format($c['new']) ?> new</span><?php endif; ?>
                    <?php if ($c['malicious'] > 0): ?><span class="report-pill danger"><?= number_format($c['malicious']) ?> malicious</span><?php endif; ?>
                    <?php if ($c['suspicious'] > 0): ?><span class="report-pill warning"><?= number_format($c['suspicious']) ?> suspicious</span><?php endif; ?>
                </span>
            </h2>

            <table class="striped report-table report-detail">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>TLD</th>
                        <th>Source</th>
                        <th>First Seen</th>
                        <th>Created</th>
                        <th>Expiration</th>
                        <th>Registrar</th>
                        <th>Name Servers</th>
                        <th>WHOIS</th>
                        <th>Tag</th>
                        <th>VirusTotal</th>
                        <th>Watchlist</th>
                        <th>Hist.</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($data['rows'] as $r):
                        $tagVal = (string)($r['tag'] ?? '');
                        $tagCell = isset($tagLabels[$tagVal])
                            ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                            : '<span class="muted">&mdash;</span>';

                        $vtCell = reportVtCell($r, $vtLabels);

                        $creation = !empty($r['creation_date']) ? substr(fmt_date((string)$r['creation_date']), 0, 10) : '—';
                        $expiration = !empty($r['expiration_date']) ? substr(fmt_date((string)$r['expiration_date']), 0, 10) : '—';
                        $sourceLabel = ((string)$r['source'] === 'ct') ? 'OpenINTEL' : 'CZDS';
                        $whoisStatus = (string)($r['whois_status'] ?? '');
                        $whoisCell = $whoisStatus === '' ? '<span class="muted">&mdash;</span>'
                            : '<span class="whois-status whois-' . htmlspecialchars($whoisStatus) . '">' . htmlspecialchars($whoisStatus) . '</span>';
                        $lastAnalysis = !empty($r['last_analysis_date']) ? substr(fmt_date((string)$r['last_analysis_date']), 0, 10) : '';
                    ?>
                    <tr>
                        <td class="domain-cell"><?= htmlspecialchars($r['domain']) ?></td>
                        <td><?= htmlspecialchars($r['tld']) ?></td>
                        <td><?= htmlspecialchars($sourceLabel) ?></td>
                        <td><?= htmlspecialchars(fmt_date($r['first_seen'])) ?></td>
                        <td><?= htmlspecialchars($creation) ?><?php if (!empty($r['_is_new'])): ?> <span class="badge-new">NEW</span><?php endif; ?></td>
                        <td><?= htmlspecialchars($expiration) ?></td>
                        <td><?= $r['registrar'] ? htmlspecialchars((string)$r['registrar']) : '<span class="muted">&mdash;</span>' ?></td>
                        <td class="ns-cell"><?= !empty($r['_ns']) ? htmlspecialchars(implode(', ', $r['_ns'])) : '<span class="muted">&mdash;</span>' ?></td>
                        <td><?= $whoisCell ?></td>
                        <td><?= $tagCell ?></td>
                        <td><?= $vtCell ?><?php if ($lastAnalysis !== ''): ?><span class="vt-detail"><?= htmlspecialchars($lastAnalysis) ?></span><?php endif; ?></td>
                        <td><?= !empty($r['in_watchlist']) ? 'Yes' : '<span class="muted">No</span>' ?></td>
                        <td><?= !empty($r['is_historical']) ? 'Yes' : '<span class="muted">No</span>' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>
    <?php endforeach; ?>

    <footer class="report-foot">
        Generated by ThreatIntelligence-TDL on <?= htmlspecialchars($generatedAt) ?> — <?= number_format($totalDomains) ?> domain(s) across <?= count($report) ?> keyword(s).
    </footer>

    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
