<?php
/**
 * Per-keyword match review.
 *
 * Lists every domain ever matched by one of the current user's keywords,
 * including matches that are now hidden from the Notifications list (tagged
 * good/bad, in the watchlist, or from a historical recheck). Read-only: this
 * page only shows data. It is reachable only from the Matches cell of the
 * Keywords page and still enforces keyword ownership (id + user_id).
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_present.php';
require_once __DIR__ . '/includes/report_queue.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$rules = reportReviewRules($db);
$repSymbol = ['malicious' => '●', 'suspicious' => '⚠', 'dga' => '⚠', 'clean' => '✓', 'not_checked' => '○', 'unproven' => '○'];

$keywordId = (int)($_GET['id'] ?? 0);

$stmt = $db->prepare("SELECT id, keyword, match_count, group_id, created_at FROM keywords WHERE id = ? AND user_id = ? LIMIT 1");
$stmt->execute([$keywordId, $userId]);
$keyword = $stmt->fetch();

$defaultNewDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));

// Groups for the "send to report" selector (default = the keyword's group).
$groupsStmt = $db->prepare("SELECT id, name FROM keyword_groups WHERE user_id = ? ORDER BY name ASC");
$groupsStmt->execute([$userId]);
$keywordGroups = $groupsStmt->fetchAll();

// Unknown or foreign keyword: do not reveal anything about it.
if (!$keyword) {
    http_response_code(404);
    $pageTitle = 'Keyword not found';
    require __DIR__ . '/templates/header.php';
    ?>
    <div class="card">
        <div class="card-head"><h2>Keyword not found</h2></div>
        <p class="muted">This keyword does not exist or does not belong to your account.</p>
        <a href="/keywords.php" class="btn waves-effect"><i class="material-icons left">arrow_back</i>Back to Keywords</a>
    </div>
    <?php
    require __DIR__ . '/templates/footer.php';
    exit;
}

// ---------- Filters (whitelisted) ----------
$search = trim($_GET['q'] ?? '');

$state = (string)($_GET['state'] ?? 'all');
$validStates = ['all', 'good', 'bad', 'observing', 'excluded', 'watchlist', 'historical', 'untagged'];
if (!in_array($state, $validStates, true)) {
    $state = 'all';
}

$source = (string)($_GET['source'] ?? 'all');
$validSources = ['all', 'czds', 'ct'];
if (!in_array($source, $validSources, true)) {
    $source = 'all';
}

// Excluded domains are hidden from the main "All states" view; "Include
// excluded" (and the dedicated Excluded filter) brings them back.
$includeExcluded = isset($_GET['incl']) && $_GET['incl'] === '1';

// Show only domains currently queued for the next report.
$queuedOnly = isset($_GET['queued']) && $_GET['queued'] === '1';

// ---------- Column sorting (never interpolate user input into SQL) ----------
$sortCols = [
    'domain'     => 'm.domain',
    'tld'        => 'm.tld',
    'first_seen' => 'm.first_seen',
    'created'    => "COALESCE(dw.creation_ts, datetime(dw.creation_date))",
    'discovered' => 'm.discovered_at',
];
$sortDefaults = ['domain' => 'asc', 'tld' => 'asc', 'first_seen' => 'desc', 'created' => 'desc', 'discovered' => 'desc'];
$sort = (string)($_GET['sort'] ?? 'discovered');
if (!isset($sortCols[$sort])) {
    $sort = 'discovered';
}
$dir = isset($_GET['dir']) ? (strtolower((string)$_GET['dir']) === 'asc' ? 'asc' : 'desc') : ($sortDefaults[$sort] ?? 'desc');
// Rows without a value (e.g. no WHOIS creation date) always sort last.
$orderBy = $sortCols[$sort] . ' IS NULL ASC, ' . $sortCols[$sort] . ' ' . strtoupper($dir);

// ---------- Pagination ----------
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 100;

$from = "FROM matches m
    LEFT JOIN domain_tags dt ON dt.domain = m.domain
    LEFT JOIN watchlist w ON w.user_id = ? AND w.domain = m.domain
    LEFT JOIN domain_whois dw ON dw.domain = m.domain";
$where = "WHERE m.keyword_id = ?";
$params = [$keywordId];

if ($search !== '') {
    $where .= " AND (m.domain LIKE ? OR m.tld LIKE ?)";
    $like = '%' . $search . '%';
    $params[] = $like;
    $params[] = $like;
}

if ($state === 'all') {
    // Main view: keep excluded domains out unless explicitly requested.
    if (!$includeExcluded) {
        $where .= " AND NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')";
    }
} elseif (in_array($state, ['good', 'bad', 'observing', 'excluded'], true)) {
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

if ($queuedOnly) {
    $where .= " AND EXISTS (SELECT 1 FROM report_queue rq WHERE rq.user_id = ? AND rq.domain = m.domain AND rq.reported_at IS NULL)";
    $params[] = $userId;
}

// The FROM clause contributes the user id for the watchlist join (first param).
$queryParams = array_merge([$userId], $params);

$countStmt = $db->prepare("SELECT COUNT(*) $from $where");
$countStmt->execute($queryParams);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

$sql = "SELECT m.id, m.domain, m.tld, m.discovered_at, m.first_seen, m.is_historical, m.source,
        dt.tag AS tag, dt.note AS tag_note,
        CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS in_watchlist
    $from
    $where
    ORDER BY $orderBy
    LIMIT $perPage OFFSET $offset";
$stmt = $db->prepare($sql);
$stmt->execute($queryParams);
$rows = $stmt->fetchAll();

// WHOIS data for the visible page (used by the Created column and the detail panel).
$domainWhois = [];
if (!empty($rows)) {
    $domains = array_column($rows, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date, creation_ts, expiration_date, registrar,
            name_servers, status, source, updated_at
        FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
    }
}

// Cached VirusTotal data for the visible rows (VT column + detail panel).
$domainVt = [];
if (!empty($rows)) {
    $domains = array_column($rows, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $vtStmt = $db->prepare("SELECT domain, verdict, malicious, suspicious, harmless, undetected,
            reputation, last_analysis_date, checked_at
        FROM domain_vt WHERE domain IN ($placeholders)");
    $vtStmt->execute($domains);
    foreach ($vtStmt->fetchAll() as $v) {
        $domainVt[$v['domain']] = $v;
    }
}

// Report-queue status for the visible rows (Report column + detail panel).
$domainQueue = [];
if (!empty($rows)) {
    $domainQueue = reportQueueStatus($db, $userId, array_column($rows, 'domain'));
}

// ---------- URL helpers (preserve id + filters) ----------
function kwmSortLink(string $col, string $label, string $currentSort, string $currentDir, array $defaults): string {
    $dir = ($col === $currentSort) ? ($currentDir === 'asc' ? 'desc' : 'asc') : ($defaults[$col] ?? 'asc');
    $q = $_GET;
    unset($q['page']);
    $q['sort'] = $col;
    $q['dir'] = $dir;
    $url = '/keyword_matches.php?' . http_build_query($q);
    $active = ($col === $currentSort);
    $arrow = $active ? ($currentDir === 'asc' ? ' &#9650;' : ' &#9660;') : '';
    $aria = $active ? ' aria-sort="' . ($currentDir === 'asc' ? 'ascending' : 'descending') . '"' : '';
    return '<a href="' . htmlspecialchars($url) . '" class="th-sort' . ($active ? ' active' : '') . '"' . $aria . '>'
        . htmlspecialchars($label) . $arrow . '</a>';
}

function kwmPageUrl(int $p): string {
    $q = $_GET;
    $q['page'] = $p;
    return '/keyword_matches.php?' . http_build_query($q);
}

$pageTitle = 'Matches: ' . $keyword['keyword'];
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2>Matches: <?= htmlspecialchars($keyword['keyword']) ?></h2>
        <a href="/keywords.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">arrow_back</i>Back to Keywords</a>
    </div>

    <p class="muted">
        Every domain ever matched by this keyword (<?= number_format((int)$keyword['match_count']) ?> total),
        including those tagged good/bad, in the watchlist or from a historical recheck.
        Excluded domains are hidden by default &mdash; tick <strong>Include excluded</strong> or pick the
        <strong>Excluded</strong> state to see them.
    </p>

    <form method="GET" class="filter-form">
        <input type="hidden" name="id" value="<?= $keywordId ?>">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="q" type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder=" ">
            <label for="q">Search domain or TLD</label>
        </div>
        <select name="state" class="browser-default compact">
            <option value="all" <?= $state === 'all' ? 'selected' : '' ?>>All states</option>
            <option value="good" <?= $state === 'good' ? 'selected' : '' ?>>Good</option>
            <option value="bad" <?= $state === 'bad' ? 'selected' : '' ?>>Bad</option>
            <option value="observing" <?= $state === 'observing' ? 'selected' : '' ?>>Observing</option>
            <option value="excluded" <?= $state === 'excluded' ? 'selected' : '' ?>>Excluded</option>
            <option value="watchlist" <?= $state === 'watchlist' ? 'selected' : '' ?>>In watchlist</option>
            <option value="historical" <?= $state === 'historical' ? 'selected' : '' ?>>Historical</option>
            <option value="untagged" <?= $state === 'untagged' ? 'selected' : '' ?>>Untagged</option>
        </select>
        <select name="source" class="browser-default compact">
            <option value="all" <?= $source === 'all' ? 'selected' : '' ?>>All sources</option>
            <option value="czds" <?= $source === 'czds' ? 'selected' : '' ?>>CZDS (zone files)</option>
            <option value="ct" <?= $source === 'ct' ? 'selected' : '' ?>>OpenINTEL (CT)</option>
        </select>
        <label class="check-inline" title="Show excluded domains in the All states view">
            <input type="checkbox" name="incl" value="1" <?= $includeExcluded ? 'checked' : '' ?>>
            <span>Include excluded</span>
        </label>
        <label class="check-inline" title="Show only domains queued for the next report">
            <input type="checkbox" name="queued" value="1" <?= $queuedOnly ? 'checked' : '' ?>>
            <span>Only queued for report</span>
        </label>
        <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">search</i>Search</button>
        <?php if ($search !== '' || $state !== 'all' || $source !== 'all' || $includeExcluded || $queuedOnly): ?>
        <a href="/keyword_matches.php?id=<?= $keywordId ?>" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">clear</i>Clear</a>
        <?php endif; ?>
    </form>

    <?php if (!empty($rows)): ?>
    <div class="section-actions">
        <label class="check-inline">
            <input type="checkbox" id="select-all">
            <span><strong>Select all visible</strong></span>
        </label>
        <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleWhois()"><i class="material-icons left">cloud_download</i>Fetch WHOIS (worker)</button>
        <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleVt()"><i class="material-icons left">verified_user</i>Check VirusTotal (worker)</button>
        <label class="check-inline" title="Report group the selected domains will be sent to">
            <span class="muted">Report group:</span>
            <select id="report-group" class="browser-default compact">
                <option value="" <?= $keyword['group_id'] === null ? 'selected' : '' ?>>Ungrouped</option>
                <?php foreach ($keywordGroups as $g): ?>
                <option value="<?= (int)$g['id'] ?>" <?= (string)$keyword['group_id'] === (string)$g['id'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <button type="button" class="btn btn-small waves-effect" onclick="sendSelectedToReport()"><i class="material-icons left">playlist_add</i>Send to report</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="removeSelectedFromReport()"><i class="material-icons left">playlist_remove</i>Remove from report</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="tagSelectedDomains('excluded')"><i class="material-icons left">block</i>Exclude selected</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="tagSelectedDomains('')"><i class="material-icons left">restore</i>Unexclude selected</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="location.reload()"><i class="material-icons left">refresh</i>Refresh</button>
    </div>
    <?php endif; ?>

    <?php if (empty($rows)): ?>
        <p class="muted">No domains match your filters.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th><?= kwmSortLink('domain', 'Domain', $sort, $dir, $sortDefaults) ?></th>
                    <th><?= kwmSortLink('tld', 'TLD', $sort, $dir, $sortDefaults) ?></th>
                    <th>VT</th>
                    <th>Tag</th>
                    <th>Report</th>
                    <th>Watchlist</th>
                    <th>Source</th>
                    <th><?= kwmSortLink('first_seen', 'First Seen', $sort, $dir, $sortDefaults) ?></th>
                    <th><?= kwmSortLink('created', 'Created', $sort, $dir, $sortDefaults) ?></th>
                    <th><?= kwmSortLink('discovered', 'Discovered', $sort, $dir, $sortDefaults) ?></th>
                    <th>Exclude</th>
                    <th>Historical</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($rows as $r):
                    $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING', 'excluded' => 'EXCLUDED'];
                    $tagVal = (string)($r['tag'] ?? '');
                    $tagCell = isset($tagLabels[$tagVal])
                        ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                        : '<span class="muted">&mdash;</span>';
                    $isExcluded = ($tagVal === 'excluded');

                    $whoisRow = $domainWhois[$r['domain']] ?? null;
                    $creationDate = $whoisRow['creation_date'] ?? null;
                    $isNew = false;
                    if ($creationDate) {
                        try {
                            $createdTs = strtotime($creationDate);
                            $isNew = $createdTs && $createdTs > strtotime("-{$defaultNewDays} days");
                        } catch (Exception $e) { $isNew = false; }
                    }
                    $creationDisplay = $creationDate ? substr(fmt_date($creationDate), 0, 10) : '—';
                    $sourceLabel = ((string)$r['source'] === 'ct') ? 'OpenINTEL' : 'CZDS';

                    $vtRow = $domainVt[$r['domain']] ?? null;
                    $vtVerdict = $vtRow ? (string)$vtRow['verdict'] : '';
                    $vtLabels = ['malicious' => 'MALICIOUS', 'dga' => 'DGA', 'suspicious' => 'SUSPICIOUS', 'clean' => 'CLEAN'];
                    $vtCell = isset($vtLabels[$vtVerdict])
                        ? '<span class="vt-badge vt-' . $vtVerdict . '">' . $vtLabels[$vtVerdict] . '</span>'
                        : '<span class="muted">&mdash;</span>';

                    $queueRow = $domainQueue[$r['domain']] ?? null;
                    $isQueued = $queueRow !== null && $queueRow['reported_at'] === null;
                    $reportCell = $isQueued
                        ? '<span class="tag-chip report" title="Queued for the next report">QUEUED</span>'
                        : '<span class="muted">&mdash;</span>';

                    // Build a snapshot-like row so the report presentation helpers
                    // render the same detail block as in the report view.
                    $ns = (!empty($whoisRow['name_servers'])) ? (json_decode((string)$whoisRow['name_servers'], true) ?: []) : [];
                    $present = [
                        'domain'             => $r['domain'],
                        'tld'                => $r['tld'],
                        'discovered_at'      => $r['discovered_at'],
                        'first_seen'         => $r['first_seen'],
                        'is_historical'      => $r['is_historical'],
                        'source'             => $r['source'],
                        'tag'                => $tagVal,
                        'tag_note'           => $r['tag_note'] ?? null,
                        'in_watchlist'       => $r['in_watchlist'],
                        'creation_date'      => $creationDate,
                        'expiration_date'    => $whoisRow['expiration_date'] ?? null,
                        'registrar'          => $whoisRow['registrar'] ?? null,
                        'name_servers'       => $whoisRow['name_servers'] ?? null,
                        'whois_status'       => $whoisRow['status'] ?? null,
                        'whois_source'       => $whoisRow['source'] ?? null,
                        'whois_updated_at'   => $whoisRow['updated_at'] ?? null,
                        'verdict'            => $vtRow['verdict'] ?? null,
                        'malicious'          => $vtRow['malicious'] ?? null,
                        'suspicious'         => $vtRow['suspicious'] ?? null,
                        'harmless'           => $vtRow['harmless'] ?? null,
                        'undetected'         => $vtRow['undetected'] ?? null,
                        'reputation'         => $vtRow['reputation'] ?? null,
                        'last_analysis_date' => $vtRow['last_analysis_date'] ?? null,
                        'vt_checked_at'      => $vtRow['checked_at'] ?? null,
                        '_ns'                => $ns,
                        '_is_new'            => $isNew,
                    ];
                    $age = reportDomainAge($present['creation_date'], gmdate('Y-m-d H:i:s'));
                    $status = reportDomainStatus($present, $rules);
                    $rep = reportReputationContextual(reportReputation($present), $age);
                    $avail = reportAvailability($present);
                    $whois = $avail['whois'];
                    $risk = reportRiskAssessment($present, $status, $avail);
                    $ttdH = reportTimeToDetectHours($present);
                    $timeline = reportTimeline($present, '');
                    $rawJson = htmlspecialchars(json_encode($present, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                ?>
                <tr data-domain="<?= htmlspecialchars($r['domain']) ?>"<?= $isExcluded ? ' data-excluded="1"' : '' ?>>
                    <td><label><input type="checkbox" class="row-check"><span></span></label></td>
                    <td>
                        <a href="javascript:void(0)" class="domain-link" onclick="toggleKwDetail(this)" aria-expanded="false"><?= reportHighlightKeyword((string)$r['domain'], (string)$keyword['keyword']) ?></a><?= reportTldBadge((string)$r['domain']) ?><?php if ($isNew): ?> <span class="badge-new">NEW</span><?php endif; ?>
                    </td>
                    <td><?= htmlspecialchars($r['tld']) ?></td>
                    <td><?= $vtCell ?></td>
                    <td><?= $tagCell ?></td>
                    <td><?= $reportCell ?></td>
                    <td><?= !empty($r['in_watchlist']) ? '<i class="material-icons tiny" title="In watchlist">star</i>' : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= $sourceLabel ?></td>
                    <td><?= htmlspecialchars(fmt_date($r['first_seen'])) ?></td>
                    <td><?= htmlspecialchars($creationDisplay) ?></td>
                    <td><?= htmlspecialchars(fmt_date($r['discovered_at'])) ?></td>
                    <td>
                        <?php if ($isExcluded): ?>
                            <button type="button" class="btn btn-small btn-outline waves-effect js-kwm-tag" data-domain="<?= htmlspecialchars($r['domain']) ?>" data-tag=""><i class="material-icons left">restore</i>Unexclude</button>
                        <?php else: ?>
                            <button type="button" class="btn btn-small btn-outline waves-effect js-kwm-tag" data-domain="<?= htmlspecialchars($r['domain']) ?>" data-tag="excluded"><i class="material-icons left">block</i>Exclude</button>
                        <?php endif; ?>
                    </td>
                    <td><?= !empty($r['is_historical']) ? '<span class="status-badge status-cancelled">Yes</span>' : '<span class="muted">No</span>' ?></td>
                </tr>
                <tr class="domain-detail-row" style="display:none;">
                    <td colspan="13">
                        <div class="domain-detail">
                            <div class="dd-grid">
                                <div class="dd-block">
                                    <h4>Assessment</h4>
                                    <dl class="dd-list">
                                        <div><dt>Risk</dt><dd><span class="risk-pill risk-<?= htmlspecialchars($risk['risk']) ?>"><?= htmlspecialchars(ucfirst($risk['risk'])) ?></span></dd></div>
                                        <div><dt>Confidence</dt><dd><?= htmlspecialchars(ucfirst($risk['confidence'])) ?></dd></div>
                                    </dl>
                                    <ul class="dd-findings">
                                        <?php foreach ($risk['reasons'] as $reason): ?>
                                            <li class="<?= strpos($reason, 'registration period') !== false ? 'reason-warn' : '' ?>"><?= htmlspecialchars($reason) ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                                <div class="dd-block">
                                    <h4>Timeline</h4>
                                    <ul class="report-timeline">
                                        <?php foreach ($timeline as $ev): ?>
                                            <li><span class="tl-dot"></span><span class="tl-date"><?= htmlspecialchars(fmt_date((string)$ev['at'])) ?></span><span class="tl-label"><?= htmlspecialchars($ev['label']) ?></span><span class="tl-source muted"><?= htmlspecialchars($ev['source']) ?></span></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                                <div class="dd-block">
                                    <h4>Registration</h4>
                                    <dl class="dd-list">
                                        <div><dt>Registrar</dt><dd><?= !empty($present['registrar']) ? htmlspecialchars((string)$present['registrar']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        <div><dt>Name servers</dt><dd><?= !empty($ns) ? htmlspecialchars(implode(', ', $ns)) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        <div><dt>WHOIS</dt><dd><span class="avail avail-<?= htmlspecialchars($whois['state']) ?>"><?= htmlspecialchars($whois['label']) ?></span></dd></div>
                                        <div><dt>Source</dt><dd><?= !empty($present['whois_source']) ? htmlspecialchars((string)$present['whois_source']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        <div><dt>Updated</dt><dd><?= !empty($present['whois_updated_at']) ? htmlspecialchars(fmt_date((string)$present['whois_updated_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                    </dl>
                                </div>
                                <div class="dd-block">
                                    <h4>Reputation</h4>
                                    <dl class="dd-list">
                                        <div><dt>VirusTotal</dt><dd><span class="rep-pill rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($repSymbol[$rep['state']] ?? '') ?> <?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?> <span class="muted"><?= htmlspecialchars($rep['detail']) ?></span><?php endif; ?></dd></div>
                                        <div><dt>Last analysis</dt><dd><?= htmlspecialchars(reportFormatDate($present['last_analysis_date'] ?? null)) ?></dd></div>
                                        <div><dt>Checked</dt><dd><?= !empty($present['vt_checked_at']) ? htmlspecialchars(fmt_date((string)$present['vt_checked_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        <div><dt>Tag</dt><dd><?= $tagCell ?></dd></div>
                                        <div><dt>Watchlist</dt><dd><?= !empty($r['in_watchlist']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
                                    </dl>
                                </div>
                                <div class="dd-block">
                                    <h4>Detection</h4>
                                    <dl class="dd-list">
                                        <div><dt>Keyword</dt><dd><?= htmlspecialchars((string)$keyword['keyword']) ?></dd></div>
                                        <div><dt>Source</dt><dd><?= htmlspecialchars($sourceLabel) ?></dd></div>
                                        <div><dt>Historical</dt><dd><?= !empty($r['is_historical']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
                                        <?php if ($ttdH !== null): ?>
                                            <div><dt>Time-to-detect</dt><dd><?= (int)$ttdH ?> h from registration to first observation</dd></div>
                                        <?php endif; ?>
                                        <?php if (!empty($present['tag_note'])): ?>
                                            <div><dt>Analyst note</dt><dd><?= htmlspecialchars((string)$present['tag_note']) ?></dd></div>
                                        <?php endif; ?>
                                    </dl>
                                    <ul class="dd-findings">
                                        <?php foreach (reportFindings($present, (string)$keyword['keyword'], $age) as $f): ?>
                                            <li class="finding-<?= htmlspecialchars($f['severity']) ?>"><strong><?= htmlspecialchars($f['label']) ?></strong><?= $f['value'] !== '' ? ': <span class="muted">' . htmlspecialchars((string)$f['value']) . '</span>' : '' ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            </div>
                            <?php if (($present['verdict'] ?? null) !== null): ?>
                            <div class="dd-vt">
                                <a class="btn btn-small btn-info waves-effect" href="https://www.virustotal.com/gui/domain/<?= rawurlencode((string)$r['domain']) ?>" target="_blank" rel="noopener"><i class="material-icons left">shield</i>Open in VirusTotal</a>
                            </div>
                            <?php endif; ?>
                            <details class="dd-raw">
                                <summary>Raw data</summary>
                                <pre><?= $rawJson ?></pre>
                            </details>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="pager">
            <span class="pagination-info">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> domain(s)
            </span>
            <ul class="pagination">
                <?php if ($page > 1): ?>
                    <li class="waves-effect"><a href="<?= htmlspecialchars(kwmPageUrl($page - 1)) ?>" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <li class="active"><a href="#!"><?= $p ?></a></li>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <li class="waves-effect"><a href="<?= htmlspecialchars(kwmPageUrl($p)) ?>"><?= $p ?></a></li>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <li class="disabled"><a href="#!">…</a></li>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <li class="waves-effect"><a href="<?= htmlspecialchars(kwmPageUrl($page + 1)) ?>" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php endif; ?>
            </ul>
        </div>
    <?php endif; ?>
</div>

<script>
// Toggle the per-domain detail row (same layout as the report view). Several
// details can be open at the same time.
function toggleKwDetail(link) {
    var row = link.closest('tr');
    if (!row) return;
    var detail = row.nextElementSibling;
    if (!detail || !detail.classList.contains('domain-detail-row')) return;
    var open = detail.style.display === 'none' || detail.style.display === '';
    detail.style.display = open ? 'table-row' : 'none';
    link.setAttribute('aria-expanded', open ? 'true' : 'false');
}
// Exclude/unexclude a single domain through the shared tag endpoint. A reload
// keeps the current state filter and counters consistent.
document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('.js-kwm-tag') : null;
    if (!btn) return;
    var domain = btn.getAttribute('data-domain');
    var tag = btn.getAttribute('data-tag') || '';
    btn.disabled = true;
    fetch('/ajax_tag_domain.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, tag: tag })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) { location.reload(); }
            else { btn.disabled = false; alert(data.error || 'Failed to update domain'); }
        })
        .catch(function () { btn.disabled = false; alert('Failed to update domain'); });
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
