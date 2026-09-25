<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report.php';
require_once __DIR__ . '/includes/report_queue.php';
require_once __DIR__ . '/includes/domain_detail.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

// Configurable "new domain" window, also used as the margin when hiding domains
// whose WHOIS creation date proves they were registered before the last scan.
$defaultNewDays = max(1, (int)(getSetting($db, 'new_domain_days', '1')));
$validDateFilters = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];

// Default visibility rules, shared by the list, the bulk delete and the counters:
//  - hidden: historical (recheck) matches, domains tagged good/bad, and domains
//    registered before the last successful scan of their TLD (validated via WHOIS);
//  - kept:  domains under observation ('observing') are never hidden by date.
$visibility = matchVisibilityClauses($db);
$goodBadClause = $visibility['good_bad'];
$observingClause = $visibility['observing'];
$oldDomainClause = $visibility['old_domain'];
$hiddenPredicate = $visibility['hidden'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

// Mark single as read
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'mark_read') {
    $notifId = (int)($_POST['notif_id'] ?? 0);
    $stmt = $db->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?");
    $stmt->execute([$notifId, $userId]);
    header('Location: /notifications.php');
    exit;
}

// Mark all as read
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'mark_all_read') {
    $stmt = $db->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$userId]);
    header('Location: /notifications.php');
    exit;
}

// Delete single notification
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    $notifId = (int)($_POST['notif_id'] ?? 0);
    $db->prepare("DELETE FROM notifications WHERE id = ? AND user_id = ?")->execute([$notifId, $userId]);
    header('Location: /notifications.php');
    exit;
}

// Delete selected notifications (current page only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_selected') {
    $selected = array_filter(array_map('intval', $_POST['selected'] ?? []));
    if (!empty($selected)) {
        $placeholders = implode(',', array_fill(0, count($selected), '?'));
        $params = array_merge($selected, [$userId]);
        $db->prepare("DELETE FROM notifications WHERE id IN ($placeholders) AND user_id = ?")->execute($params);
    }
    header('Location: /notifications.php');
    exit;
}

// Delete ALL notifications matching current filters
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_all_matching') {
    $delWhere = "WHERE n.user_id = ? AND NOT EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain)";
    $delParams = [$userId, $userId];
    $qFilter = trim($_POST['q'] ?? '');
    $dateFilterPost = $_POST['date'] ?? 'all';
    $unreadFilterPost = isset($_POST['unread_only']) && $_POST['unread_only'] === '1';
    $archivedFilterPost = isset($_POST['archived']) && $_POST['archived'] === '1';
    $observingFilterPost = isset($_POST['observing']) && $_POST['observing'] === '1';

    if ($observingFilterPost) {
        $delWhere .= " AND " . $observingClause;
    } elseif (!$archivedFilterPost) {
        $delWhere .= " AND NOT (" . $hiddenPredicate . ")";
    }

    if ($qFilter !== '') {
        $delWhere .= " AND (m.domain LIKE ? OR m.tld LIKE ? OR k.keyword LIKE ?)";
        $like = '%' . $qFilter . '%';
        $delParams[] = $like;
        $delParams[] = $like;
        $delParams[] = $like;
    }
    if ($unreadFilterPost) {
        $delWhere .= " AND n.is_read = 0";
    }
    if (!empty($validDateFilters[$dateFilterPost])) {
        $delWhere .= " AND m.discovered_at >= datetime('now', ?)";
        $delParams[] = $validDateFilters[$dateFilterPost];
    }

    // SQLite does not allow DELETE FROM table WHERE id IN (SELECT FROM same_table)
    // so we fetch the IDs first, then delete them in a separate query.
    $idsStmt = $db->prepare("SELECT n.id FROM notifications n JOIN matches m ON n.match_id = m.id JOIN keywords k ON m.keyword_id = k.id $delWhere");
    $idsStmt->execute($delParams);
    $ids = $idsStmt->fetchAll(PDO::FETCH_COLUMN);
    if (!empty($ids)) {
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $db->prepare("DELETE FROM notifications WHERE id IN ($placeholders) AND user_id = ?")
            ->execute(array_merge($ids, [$userId]));
    }

    $redirect = '/notifications.php';
    if ($qFilter !== '' || $dateFilterPost !== 'all' || $unreadFilterPost || $archivedFilterPost || $observingFilterPost) {
        $qs = [];
        if ($qFilter !== '') $qs['q'] = $qFilter;
        if ($dateFilterPost !== 'all') $qs['date'] = $dateFilterPost;
        if ($unreadFilterPost) $qs['unread_only'] = '1';
        if ($archivedFilterPost) $qs['archived'] = '1';
        if ($observingFilterPost) $qs['observing'] = '1';
        $redirect .= '?' . http_build_query($qs);
    }
    header('Location: ' . $redirect);
    exit;
}

// Search / filter params
$search = trim($_GET['q'] ?? '');
$unreadOnly = isset($_GET['unread_only']) && $_GET['unread_only'] === '1';
$dateFilter = $_GET['date'] ?? 'all';
$includeArchived = isset($_GET['archived']) && $_GET['archived'] === '1';
$observingOnly = isset($_GET['observing']) && $_GET['observing'] === '1';

// Column sorting (whitelisted, never interpolate user input into SQL).
$notifSortCols = [
    'status'     => 'n.is_read',
    'domain'     => 'm.domain',
    'tld'        => 'm.tld',
    'keyword'    => 'k.keyword',
    'first_seen' => 'm.first_seen',
    'created'    => 'COALESCE(dws.creation_ts, datetime(dws.creation_date))',
    'discovered' => 'm.discovered_at',
];
$notifSortDefaults = [
    'status' => 'asc', 'domain' => 'asc', 'tld' => 'asc', 'keyword' => 'asc',
    'first_seen' => 'desc', 'created' => 'desc', 'discovered' => 'desc',
];
$sort = $_GET['sort'] ?? '';
if (!isset($notifSortCols[$sort])) {
    $sort = '';
}
$dir = isset($_GET['dir']) ? (strtolower((string)$_GET['dir']) === 'asc' ? 'asc' : 'desc') : 'desc';
$orderBy = $sort !== '' ? ($notifSortCols[$sort] . ' ' . strtoupper($dir)) : 'n.created_at DESC';

// Configurable threshold for "new" badge/filter (default from admin setting)
$newDays = isset($_GET['new_days']) ? max(1, min(365, (int)$_GET['new_days'])) : null;
$newOnly = $newDays !== null;

// Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;
$offset = ($page - 1) * $perPage;

$where = "WHERE n.user_id = ? AND (n.kind = 'intelligence' OR NOT EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain))";
$params = [$userId, $userId];

// Default view hides historical, good/bad and validated-as-old domains, but
// keeps domains under observation. The "Only observing" filter shows just those,
// and the "Include tagged / historical" toggle reveals the hidden ones.
if ($observingOnly) {
    $where .= " AND " . $observingClause;
} elseif (!$includeArchived) {
    $where .= " AND (n.kind = 'intelligence' OR NOT (" . $hiddenPredicate . "))";
}

if ($search !== '') {
    $where .= " AND (m.domain LIKE ? OR m.tld LIKE ? OR k.keyword LIKE ?)";
    $like = '%' . $search . '%';
    $params[] = $like;
    $params[] = $like;
    $params[] = $like;
}

if ($unreadOnly) {
    $where .= " AND n.is_read = 0";
}

if ($newOnly) {
    $where .= " AND EXISTS (SELECT 1 FROM domain_whois dw WHERE dw.domain = m.domain AND dw.creation_date >= datetime('now', '-' || ? || ' days'))";
    $params[] = $newDays;
}

if (!empty($validDateFilters[$dateFilter])) {
    $where .= " AND m.discovered_at >= datetime('now', ?)";
    $params[] = $validDateFilters[$dateFilter];
}

// Count total
$countSql = "SELECT COUNT(*) FROM notifications n JOIN matches m ON n.match_id = m.id JOIN keywords k ON m.keyword_id = k.id $where";
$totalStmt = $db->prepare($countSql);
$totalStmt->execute($params);
$total = (int)$totalStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));

// Count how many are hidden because they are in watchlist
$hiddenCountStmt = $db->prepare("SELECT COUNT(*) FROM notifications n JOIN matches m ON n.match_id = m.id WHERE n.user_id = ? AND EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain)");
$hiddenCountStmt->execute([$userId, $userId]);
$hiddenCount = (int)$hiddenCountStmt->fetchColumn();

// Count how many are hidden (historical, good/bad, or validated as old). Domains
// under observation are visible and therefore not counted here.
$archivedCount = 0;
if (!$includeArchived && !$observingOnly) {
    $archivedCountStmt = $db->prepare(
        "SELECT COUNT(*) FROM notifications n JOIN matches m ON n.match_id = m.id "
        . "WHERE n.user_id = ? AND n.kind <> 'intelligence' AND (" . $hiddenPredicate . ")"
    );
    $archivedCountStmt->execute([$userId]);
    $archivedCount = (int)$archivedCountStmt->fetchColumn();
}

$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

// Fetch page. The domain_whois join lets "Created" be sorted server-side.
$sql = "SELECT n.id, n.is_read, n.created_at, n.kind, m.domain, m.tld, m.discovered_at, m.first_seen, m.is_historical, m.source, k.keyword 
    FROM notifications n 
    JOIN matches m ON n.match_id = m.id 
    JOIN keywords k ON m.keyword_id = k.id 
    LEFT JOIN domain_whois dws ON dws.domain = m.domain
    $where 
    ORDER BY $orderBy 
    LIMIT $perPage OFFSET $offset";
$stmt = $db->prepare($sql);
$stmt->execute($params);
$notifications = $stmt->fetchAll();

// Load domain tags for visible rows
$domainTags = [];
if (!empty($notifications)) {
    $domainsOnPage = array_column($notifications, 'domain');
    $placeholders = implode(',', array_fill(0, count($domainsOnPage), '?'));
    $tagStmt = $db->prepare("SELECT domain, tag, note FROM domain_tags WHERE domain IN ($placeholders)");
    $tagStmt->execute($domainsOnPage);
    foreach ($tagStmt->fetchAll() as $t) {
        $domainTags[$t['domain']] = $t;
    }
}

// Load / prefetch domain whois for visible rows
require_once __DIR__ . '/includes/whois.php';
$domainWhois = [];
if (!empty($notifications)) {
    $domainsOnPage = array_column($notifications, 'domain');
    $placeholders = implode(',', array_fill(0, count($domainsOnPage), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date, creation_ts, expiration_date, registrar,
            name_servers, status, source, updated_at
        FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domainsOnPage);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
    }
    // Missing entries are left empty; WHOIS is filled on demand by the worker
    // (no blocking network calls while rendering the page).
}

// Load cached VirusTotal verdicts for the visible rows
$domainVt = [];
if (!empty($notifications)) {
    $domainsOnPage = array_column($notifications, 'domain');
    $placeholders = implode(',', array_fill(0, count($domainsOnPage), '?'));
    $vtStmt = $db->prepare("SELECT domain, verdict, malicious, suspicious, harmless, undetected,
            reputation, last_analysis_date, checked_at
        FROM domain_vt WHERE domain IN ($placeholders)");
    $vtStmt->execute($domainsOnPage);
    foreach ($vtStmt->fetchAll() as $v) {
        $domainVt[$v['domain']] = $v;
    }
}

// Load cached abuse.ch (URLhaus + ThreatFox) validations for the visible rows.
$domainAbusech = [];
if (!empty($notifications)) {
    $domainsOnPage = array_column($notifications, 'domain');
    $placeholders = implode(',', array_fill(0, count($domainsOnPage), '?'));
    $abStmt = $db->prepare("SELECT domain, verdict, status, error, urlhaus_verdict, urlhaus_url_count, urlhaus_online,
            urlhaus_dbl, threatfox_verdict, threatfox_matches, threat_type, malware_family,
            confidence, tags, last_analysis_date, checked_at
        FROM domain_abusech WHERE domain IN ($placeholders)");
    $abStmt->execute($domainsOnPage);
    foreach ($abStmt->fetchAll() as $a) {
        $domainAbusech[$a['domain']] = $a;
    }
}

// Load cached Cloudflare Radar (URL Scanner + DNS) for the visible rows.
$domainCfscan = [];
if (!empty($notifications)) {
    $domainsOnPage = array_column($notifications, 'domain');
    $placeholders = implode(',', array_fill(0, count($domainsOnPage), '?'));
    $cfStmt = $db->prepare("SELECT * FROM domain_cfscan WHERE domain IN ($placeholders)");
    $cfStmt->execute($domainsOnPage);
    foreach ($cfStmt->fetchAll() as $c) {
        $domainCfscan[$c['domain']] = $c;
    }
}

// Report-queue status for the visible rows.
$domainQueue = [];
if (!empty($notifications)) {
    $domainQueue = reportQueueStatus($db, $userId, array_column($notifications, 'domain'));
}

// Report review rules (used by the rich domain detail block).
$rules = reportReviewRules($db);

// Helper to build pagination URLs preserving filters
function notifUrl(int $p, string $search, string $date, bool $unread, ?int $newDays, bool $archived = false, bool $observing = false, string $sort = '', string $dir = ''): string {
    $q = ['page' => $p];
    if ($search !== '') $q['q'] = $search;
    if ($date !== 'all') $q['date'] = $date;
    if ($unread) $q['unread_only'] = '1';
    if ($newDays !== null) $q['new_days'] = (string)$newDays;
    if ($archived) $q['archived'] = '1';
    if ($observing) $q['observing'] = '1';
    if ($sort !== '') { $q['sort'] = $sort; $q['dir'] = $dir; }
    return '/notifications.php?' . http_build_query($q);
}

/**
 * Render a sortable table header link, preserving the current filters.
 */
function notifSortLink(string $col, string $label, string $currentSort, string $currentDir, array $defaults): string {
    $dir = ($col === $currentSort) ? ($currentDir === 'asc' ? 'desc' : 'asc') : ($defaults[$col] ?? 'asc');
    $q = $_GET;
    unset($q['page']);
    $q['sort'] = $col;
    $q['dir'] = $dir;
    $url = '/notifications.php?' . http_build_query($q);
    $active = ($col === $currentSort);
    $arrow = $active ? ($currentDir === 'asc' ? ' &#9650;' : ' &#9660;') : '';
    $aria = $active ? ' aria-sort="' . ($currentDir === 'asc' ? 'ascending' : 'descending') . '"' : '';
    return '<a href="' . htmlspecialchars($url) . '" class="th-sort' . ($active ? ' active' : '') . '"' . $aria . '>'
        . htmlspecialchars($label) . $arrow . '</a>';
}

$pageTitle = 'Notifications';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2>Notifications</h2>
        <?php if (!empty($notifications) || $hiddenCount > 0): ?>
        <form method="POST" style="margin: 0;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="mark_all_read">
            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">done_all</i>Mark All Read</button>
        </form>
        <?php endif; ?>
    </div>

    <form method="GET" id="filter-form" class="filter-form">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="q" type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder=" ">
            <label for="q">Search domain, TLD or keyword</label>
        </div>
        <select name="date" class="browser-default compact">
            <option value="all" <?= $dateFilter === 'all' ? 'selected' : '' ?>>All time</option>
            <option value="24h" <?= $dateFilter === '24h' ? 'selected' : '' ?>>Last 24h</option>
            <option value="7d" <?= $dateFilter === '7d' ? 'selected' : '' ?>>Last 7 days</option>
            <option value="30d" <?= $dateFilter === '30d' ? 'selected' : '' ?>>Last 30 days</option>
        </select>
        <label class="check-inline">
            <input type="checkbox" name="unread_only" value="1" <?= $unreadOnly ? 'checked' : '' ?>>
            <span>Unread only</span>
        </label>
        <div class="check-inline">
            <span class="muted">Created &le;</span>
            <input type="number" name="new_days" value="<?= $newDays ?? $defaultNewDays ?>" min="1" max="365" class="browser-default compact num-input">
            <span class="muted">day(s)</span>
        </div>
        <label class="check-inline" title="Reveal hidden domains: tagged good/bad, recheck matches, or validated as registered before the last scan">
            <input type="checkbox" name="archived" value="1" <?= $includeArchived ? 'checked' : '' ?>>
            <span>Include tagged / historical / old</span>
        </label>
        <label class="check-inline" title="Show only domains under observation (insufficient info)">
            <input type="checkbox" name="observing" value="1" <?= $observingOnly ? 'checked' : '' ?>>
            <span>Only observing</span>
        </label>
        <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">search</i>Search</button>
        <?php if ($search !== '' || $unreadOnly || $newDays !== null || $dateFilter !== 'all' || $includeArchived || $observingOnly): ?>
        <a href="/notifications.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">clear</i>Clear</a>
        <?php endif; ?>
    </form>

    <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all' || $includeArchived || $observingOnly): ?>
    <form method="POST" class="section-actions">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="delete_all_matching">
        <input type="hidden" name="q" value="<?= htmlspecialchars($search) ?>">
        <input type="hidden" name="date" value="<?= htmlspecialchars($dateFilter) ?>">
        <input type="hidden" name="unread_only" value="<?= $unreadOnly ? '1' : '0' ?>">
        <input type="hidden" name="archived" value="<?= $includeArchived ? '1' : '0' ?>">
        <input type="hidden" name="observing" value="<?= $observingOnly ? '1' : '0' ?>">
        <button type="submit" class="btn btn-danger waves-effect" onclick="return confirm('This will delete ALL <?= $total ?> notification(s) matching your current filter across every page. This cannot be undone. Are you sure?')"><i class="material-icons left">delete_sweep</i>Delete All Matching Results (<?= $total ?>)</button>
    </form>
    <?php endif; ?>

    <?php if ($hiddenCount > 0): ?>
        <div class="notice notice-warning">
            <i class="material-icons">star</i>
            <div><?= $hiddenCount ?> notification(s) hidden because the domain(s) are in your <a href="/watchlist.php"><strong>Watchlist</strong></a>.</div>
        </div>
    <?php endif; ?>
    <?php if ($archivedCount > 0): ?>
        <div class="notice notice-info">
            <i class="material-icons">inventory_2</i>
            <div><?= $archivedCount ?> notification(s) hidden because they were tagged good/bad, come from a historical recheck, or were registered before the last scan. <a href="/notifications.php?archived=1"><strong>Show them</strong></a>.</div>
        </div>
    <?php endif; ?>
    <?php if ($observingOnly): ?>
        <div class="notice notice-warning">
            <i class="material-icons">help_outline</i>
            <div>Showing only domains under observation. <a href="/notifications.php"><strong>Show all</strong></a>.</div>
        </div>
    <?php endif; ?>
    <?php if (empty($notifications)): ?>
        <p class="muted">No notifications to display.<?php if ($hiddenCount > 0): ?> The remaining <?= $hiddenCount ?> are in your <a href="/watchlist.php">Watchlist</a>.<?php endif; ?><?php if ($archivedCount > 0): ?> <?= $archivedCount ?> are hidden (use the toggle above to show them).<?php endif; ?></p>
    <?php else: ?>
        <form method="POST" id="bulk-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="delete_selected">
            <div class="section-actions">
                <label class="check-inline">
                    <input type="checkbox" id="select-all">
                    <span><strong>Select all visible</strong></span>
                </label>
                <button type="submit" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Delete selected notifications?')"><i class="material-icons left">delete</i>Delete Selected</button>
                <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleWhois()"><i class="material-icons left">cloud_download</i>Fetch WHOIS (worker)</button>
                <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleVt()"><i class="material-icons left">verified_user</i>Check VirusTotal (worker)</button>
                <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleAbusech()"><i class="material-icons left">gpp_maybe</i>Check Abuse.ch</button>
                <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleCfscan()"><i class="material-icons left">cloud</i>Check Cloudflare</button>
                <button type="button" class="btn btn-small waves-effect" onclick="fetchVisibleCfdns()"><i class="material-icons left">public</i>Cloudflare DNS</button>
                <button type="button" class="btn btn-small waves-effect" onclick="sendSelectedToReport()"><i class="material-icons left">playlist_add</i>Send to report</button>
                <button type="button" class="btn btn-small btn-outline waves-effect" onclick="removeSelectedFromReport()"><i class="material-icons left">playlist_remove</i>Remove from report</button>
                <button type="button" class="btn btn-small btn-outline waves-effect" onclick="location.reload()" title="Reload this list with the current filters"><i class="material-icons left">refresh</i>Refresh</button>
                <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all' || $includeArchived || $observingOnly): ?>
                <button type="submit" formaction="/notifications.php" formmethod="POST" class="btn btn-small btn-danger waves-effect" name="action" value="delete_all_matching" onclick="return confirm('This will delete ALL <?= $total ?> notification(s) matching your current filter across every page. This cannot be undone. Are you sure?')"><i class="material-icons left">delete_sweep</i>Delete All Matching (<?= $total ?>)</button>
                <?php endif; ?>
            </div>
            <!-- Hidden filter params for delete_all_matching -->
            <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all' || $includeArchived || $observingOnly): ?>
            <input type="hidden" name="q" value="<?= htmlspecialchars($search) ?>">
            <input type="hidden" name="date" value="<?= htmlspecialchars($dateFilter) ?>">
            <input type="hidden" name="unread_only" value="<?= $unreadOnly ? '1' : '0' ?>">
            <input type="hidden" name="archived" value="<?= $includeArchived ? '1' : '0' ?>">
            <input type="hidden" name="observing" value="<?= $observingOnly ? '1' : '0' ?>">
            <?php endif; ?>
        </form>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th><?= notifSortLink('status', 'Status', $sort, $dir, $notifSortDefaults) ?></th>
                    <th><?= notifSortLink('domain', 'Domain', $sort, $dir, $notifSortDefaults) ?></th>
                    <th>VT</th>
                    <th>Abuse.ch</th>
                    <th>CF</th>
                    <th><?= notifSortLink('tld', 'TLD', $sort, $dir, $notifSortDefaults) ?></th>
                    <th><?= notifSortLink('keyword', 'Keyword', $sort, $dir, $notifSortDefaults) ?></th>
                    <th><?= notifSortLink('first_seen', 'First Seen', $sort, $dir, $notifSortDefaults) ?></th>
                    <th><?= notifSortLink('created', 'Created', $sort, $dir, $notifSortDefaults) ?></th>
                    <th><?= notifSortLink('discovered', 'Discovered', $sort, $dir, $notifSortDefaults) ?></th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($notifications as $n): 
                    $dtag = $domainTags[$n['domain']] ?? null;
                    $tagBadge = '';
                    if ($dtag) {
                        $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];
                        $tagVal = $dtag['tag'];
                        $cls = in_array($tagVal, ['good', 'bad', 'observing'], true) ? $tagVal : 'bad';
                        $tagBadge = ' <span class="tag-chip ' . $cls . '">' . ($tagLabels[$tagVal] ?? strtoupper($tagVal)) . '</span>';
                    }
                    $intelBadge = (($n['kind'] ?? 'match') === 'intelligence')
                        ? ' <span class="tag-chip intel" title="Intelligence: tracked domain activation">INTELLIGENCE</span>'
                        : '';
                    $whoisRow = $domainWhois[$n['domain']] ?? null;
                    $creationDate = $whoisRow['creation_date'] ?? null;
                    $isNew = false;
                    if ($creationDate) {
                        try {
                            $createdTs = strtotime($creationDate);
                            $isNew = $createdTs && $createdTs > strtotime("-{$defaultNewDays} days");
                        } catch (Exception $e) { $isNew = false; }
                    }
                    $creationDisplay = $creationDate ? substr(fmt_date($creationDate), 0, 10) : '—';
                    $vtRow = $domainVt[$n['domain']] ?? null;
                    $vtVerdict = $vtRow ? (string)$vtRow['verdict'] : '';
                    $vtLabels = ['malicious' => 'MALICIOUS', 'dga' => 'DGA', 'suspicious' => 'SUSPICIOUS', 'clean' => 'CLEAN'];
                    $vtCell = isset($vtLabels[$vtVerdict])
                        ? '<span class="vt-badge vt-' . $vtVerdict . '">' . $vtLabels[$vtVerdict] . '</span>'
                        : '<span class="muted">&mdash;</span>';
                    $abuseRow = $domainAbusech[$n['domain']] ?? null;
                    $abuseCell = abusechBadge($abuseRow);
                    $cfRow = $domainCfscan[$n['domain']] ?? null;
                    $cfCell = cfscanBadge($cfRow);
                    $qRow = $domainQueue[$n['domain']] ?? null;
                    $queueBadge = ($qRow !== null && $qRow['reported_at'] === null)
                        ? ' <span class="tag-chip report" title="Queued for the next report">QUEUED</span>'
                        : '';
                    $ns = (!empty($whoisRow['name_servers'])) ? (json_decode((string)$whoisRow['name_servers'], true) ?: []) : [];
                    $present = [
                        'domain'             => $n['domain'],
                        'tld'                => $n['tld'],
                        'discovered_at'      => $n['discovered_at'],
                        'first_seen'         => $n['first_seen'],
                        'is_historical'      => $n['is_historical'] ?? 0,
                        'source'             => $n['source'] ?? null,
                        'tag'                => (string)($dtag['tag'] ?? ''),
                        'tag_note'           => $dtag['note'] ?? null,
                        'in_watchlist'       => 0,
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
                    ] + abusechPresentKeys($abuseRow)
                      + cfscanPresentKeys($cfRow);
                    $detailDomainArg = htmlspecialchars(addslashes($n['domain']));
                ?>
                <tr class="<?= $n['is_read'] ? '' : 'unread' ?>" data-domain="<?= htmlspecialchars($n['domain']) ?>">
                    <td><label><input type="checkbox" name="selected[]" value="<?= (int)$n['id'] ?>" class="row-check" form="bulk-form"><span></span></label></td>
                    <td><?= $n['is_read'] ? '<span class="status-badge status-cancelled">Read</span>' : '<span class="status-badge status-pending">Unread</span>' ?></td>
                    <td><a href="javascript:void(0)" class="domain-link" onclick="toggleDomainDetail(this, '<?= htmlspecialchars(addslashes($n['domain'])) ?>')"><?= htmlspecialchars($n['domain']) ?></a><?= $intelBadge ?><?= $tagBadge ?><?= $queueBadge ?></td>
                    <td><?= $vtCell ?></td>
                    <td><?= $abuseCell ?></td>
                    <td><?= $cfCell ?></td>
                    <td><?= htmlspecialchars($n['tld']) ?></td>
                    <td><?= htmlspecialchars($n['keyword']) ?></td>
                    <td><?= htmlspecialchars(fmt_date($n['first_seen'])) ?></td>
                    <td><?= htmlspecialchars($creationDisplay) ?><?php if ($isNew): ?> <span class="badge-new">NEW</span><?php endif; ?></td>
                    <td><?= htmlspecialchars(fmt_date($n['discovered_at'])) ?></td>
                    <td>
                        <div class="action-menu">
                            <button type="button" class="action-menu-btn" aria-label="Row actions" aria-haspopup="true" onclick="toggleMenu(this)"><i class="material-icons">more_vert</i></button>
                            <div class="action-menu-dropdown">
                                <?php if (!$n['is_read']): ?>
                                <form method="POST" style="margin: 0;">
                                    <?php csrfField(); ?>
                                    <input type="hidden" name="action" value="mark_read">
                                    <input type="hidden" name="notif_id" value="<?= (int)$n['id'] ?>">
                                    <button type="submit"><i class="material-icons">mark_email_read</i>Mark as read</button>
                                </form>
                                <?php endif; ?>
                                <button type="button" class="menu-good" onclick="ddTag('<?= $detailDomainArg ?>','good')"><i class="material-icons">thumb_up</i>Mark Good</button>
                                <button type="button" class="menu-bad" onclick="ddTag('<?= $detailDomainArg ?>','bad')"><i class="material-icons">thumb_down</i>Mark Bad</button>
                                <button type="button" class="menu-observing" onclick="ddTag('<?= $detailDomainArg ?>','observing')"><i class="material-icons">help_outline</i>Insufficient info</button>
                                <button type="button" onclick="ddWatchlist('<?= $detailDomainArg ?>')"><i class="material-icons">star</i>Add to Watchlist</button>
                                <hr>
                                <form method="POST" style="margin: 0;" onsubmit="return confirm('Delete this notification?')">
                                    <?php csrfField(); ?>
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="notif_id" value="<?= (int)$n['id'] ?>">
                                    <button type="submit" class="menu-danger"><i class="material-icons">delete</i>Delete</button>
                                </form>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr class="domain-detail-row" data-domain="<?= htmlspecialchars($n['domain']) ?>" style="display:none;">
                    <td colspan="12"><?= renderDomainDetail($present, [$n['keyword']], $rules) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="pager">
            <span class="pagination-info">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> notifications
            </span>
            <ul class="pagination">
                <?php if ($page > 1): ?>
                    <li class="waves-effect"><a href="<?= htmlspecialchars(notifUrl($page - 1, $search, $dateFilter, $unreadOnly, $newDays, $includeArchived, $observingOnly, $sort, $dir)) ?>" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <li class="active"><a href="#!"><?= $p ?></a></li>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <li class="waves-effect"><a href="<?= htmlspecialchars(notifUrl($p, $search, $dateFilter, $unreadOnly, $newDays, $includeArchived, $observingOnly, $sort, $dir)) ?>"><?= $p ?></a></li>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <li class="disabled"><a href="#!">…</a></li>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <li class="waves-effect"><a href="<?= htmlspecialchars(notifUrl($page + 1, $search, $dateFilter, $unreadOnly, $newDays, $includeArchived, $observingOnly, $sort, $dir)) ?>" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php endif; ?>
            </ul>
        </div>

        <script>
        document.getElementById('select-all').addEventListener('change', function(e) {
            document.querySelectorAll('.row-check').forEach(cb => cb.checked = e.target.checked);
        });

        function closeActionMenus() {
            document.querySelectorAll('.action-menu-dropdown.active').forEach(function (d) {
                d.classList.remove('active');
                d.style.position = '';
                d.style.top = '';
                d.style.left = '';
            });
        }
        function toggleMenu(btn) {
            const dropdown = btn.nextElementSibling;
            const isOpen = dropdown.classList.contains('active');
            closeActionMenus();
            if (isOpen) return;
            // Fixed positioning escapes the table's overflow clipping on small screens.
            dropdown.classList.add('active');
            const r = btn.getBoundingClientRect();
            const w = dropdown.offsetWidth || 200;
            let left = r.right - w;
            if (left < 8) left = 8;
            const maxLeft = window.innerWidth - w - 8;
            if (left > maxLeft) left = Math.max(8, maxLeft);
            let top = r.bottom + 4;
            const h = dropdown.offsetHeight || 0;
            if (top + h > window.innerHeight - 8) {
                top = Math.max(8, r.top - h - 4);
            }
            dropdown.style.position = 'fixed';
            dropdown.style.top = top + 'px';
            dropdown.style.left = left + 'px';
        }
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.action-menu')) closeActionMenus();
        });
        window.addEventListener('scroll', closeActionMenus, true);
        window.addEventListener('resize', closeActionMenus);
        </script>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
