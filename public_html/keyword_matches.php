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
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$keywordId = (int)($_GET['id'] ?? 0);

$stmt = $db->prepare("SELECT id, keyword, match_count, created_at FROM keywords WHERE id = ? AND user_id = ? LIMIT 1");
$stmt->execute([$keywordId, $userId]);
$keyword = $stmt->fetch();

$defaultNewDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));

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

// ---------- Column sorting (never interpolate user input into SQL) ----------
$sortCols = [
    'domain'     => 'm.domain',
    'tld'        => 'm.tld',
    'first_seen' => 'm.first_seen',
    'discovered' => 'm.discovered_at',
];
$sortDefaults = ['domain' => 'asc', 'tld' => 'asc', 'first_seen' => 'desc', 'discovered' => 'desc'];
$sort = (string)($_GET['sort'] ?? 'discovered');
if (!isset($sortCols[$sort])) {
    $sort = 'discovered';
}
$dir = isset($_GET['dir']) ? (strtolower((string)$_GET['dir']) === 'asc' ? 'asc' : 'desc') : ($sortDefaults[$sort] ?? 'desc');
$orderBy = $sortCols[$sort] . ' ' . strtoupper($dir);

// ---------- Pagination ----------
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 100;

$from = "FROM matches m
    LEFT JOIN domain_tags dt ON dt.domain = m.domain
    LEFT JOIN watchlist w ON w.user_id = ? AND w.domain = m.domain";
$where = "WHERE m.keyword_id = ?";
$params = [$keywordId];

if ($search !== '') {
    $where .= " AND (m.domain LIKE ? OR m.tld LIKE ?)";
    $like = '%' . $search . '%';
    $params[] = $like;
    $params[] = $like;
}

if (in_array($state, ['good', 'bad', 'observing', 'excluded'], true)) {
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

// The FROM clause contributes the user id for the watchlist join (first param).
$queryParams = array_merge([$userId], $params);

$countStmt = $db->prepare("SELECT COUNT(*) $from $where");
$countStmt->execute($queryParams);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

$sql = "SELECT m.id, m.domain, m.tld, m.discovered_at, m.first_seen, m.is_historical, m.source,
        dt.tag AS tag,
        CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS in_watchlist
    $from
    $where
    ORDER BY $orderBy
    LIMIT $perPage OFFSET $offset";
$stmt = $db->prepare($sql);
$stmt->execute($queryParams);
$rows = $stmt->fetchAll();

// WHOIS creation date (only for the visible page) to flag recently registered domains.
$domainWhois = [];
if (!empty($rows)) {
    $domains = array_column($rows, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
    }
}

// Cached VirusTotal verdicts for the visible rows (shown in the VT column).
$domainVt = [];
if (!empty($rows)) {
    $domains = array_column($rows, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $vtStmt = $db->prepare("SELECT domain, verdict FROM domain_vt WHERE domain IN ($placeholders)");
    $vtStmt->execute($domains);
    foreach ($vtStmt->fetchAll() as $v) {
        $domainVt[$v['domain']] = $v;
    }
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
        <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">search</i>Search</button>
        <?php if ($search !== '' || $state !== 'all' || $source !== 'all'): ?>
        <a href="/keyword_matches.php?id=<?= $keywordId ?>" class="btn btn-small btn-danger waves-effect"><i class="material-icons left">clear</i>Clear</a>
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
                    <th>Watchlist</th>
                    <th>Source</th>
                    <th><?= kwmSortLink('first_seen', 'First Seen', $sort, $dir, $sortDefaults) ?></th>
                    <th>Created</th>
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
                ?>
                <tr data-domain="<?= htmlspecialchars($r['domain']) ?>"<?= $isExcluded ? ' data-excluded="1"' : '' ?>>
                    <td><label><input type="checkbox" class="row-check"><span></span></label></td>
                    <td><strong><?= htmlspecialchars($r['domain']) ?></strong></td>
                    <td><?= htmlspecialchars($r['tld']) ?></td>
                    <td><?= $vtCell ?></td>
                    <td><?= $tagCell ?></td>
                    <td><?= !empty($r['in_watchlist']) ? '<i class="material-icons tiny" title="In watchlist">star</i>' : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= $sourceLabel ?></td>
                    <td><?= htmlspecialchars(fmt_date($r['first_seen'])) ?></td>
                    <td><?= htmlspecialchars($creationDisplay) ?><?php if ($isNew): ?> <span class="badge-new">NEW</span><?php endif; ?></td>
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
