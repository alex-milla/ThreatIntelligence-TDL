<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_present.php';
require_once __DIR__ . '/includes/domain_detail.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

// Remove from watchlist
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'remove') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $db->prepare("DELETE FROM watchlist WHERE id = ? AND user_id = ?")->execute([$id, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Update note
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_note') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $note = trim($_POST['note'] ?? '');
    $db->prepare("UPDATE watchlist SET note = ? WHERE id = ? AND user_id = ?")->execute([$note, $id, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Set group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'set_group') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $groupId = $_POST['group_id'] === '' ? null : (int)$_POST['group_id'];
    $db->prepare("UPDATE watchlist SET group_id = ? WHERE id = ? AND user_id = ?")->execute([$groupId, $id, $userId]);
    $redirect = '/watchlist.php';
    if (!empty($_GET['group'])) $redirect .= '?group=' . urlencode($_GET['group']);
    header('Location: ' . $redirect);
    exit;
}

// Create group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_group') {
    $name = trim($_POST['group_name'] ?? '');
    if ($name !== '') {
        $db->prepare("INSERT INTO watchlist_groups (user_id, name) VALUES (?, ?)") ->execute([$userId, $name]);
    }
    header('Location: /watchlist.php');
    exit;
}

// Delete group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    // Move domains to ungrouped first
    $db->prepare("UPDATE watchlist SET group_id = NULL WHERE group_id = ? AND user_id = ?") ->execute([$groupId, $userId]);
    $db->prepare("DELETE FROM watchlist_groups WHERE id = ? AND user_id = ?") ->execute([$groupId, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Group filter: empty means ungrouped (group_id IS NULL)
$groupFilter = $_GET['group'] ?? '';

// Load groups
$groupStmt = $db->prepare("SELECT id, name FROM watchlist_groups WHERE user_id = ? ORDER BY name ASC");
$groupStmt->execute([$userId]);
$groups = $groupStmt->fetchAll();
$groupsById = [];
foreach ($groups as $g) {
    $groupsById[(int)$g['id']] = $g['name'];
}

// Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;

// Build WHERE: default view shows only ungrouped domains
$where = "WHERE w.user_id = ?";
$params = [$userId];

if ($groupFilter === '' || $groupFilter === '0') {
    $where .= " AND w.group_id IS NULL";
} elseif (ctype_digit($groupFilter)) {
    $where .= " AND w.group_id = ?";
    $params[] = (int)$groupFilter;
}

// Count total
$totalStmt = $db->prepare("SELECT COUNT(*) FROM watchlist w $where");
$totalStmt->execute($params);
$total = (int)$totalStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

// Fetch
$stmt = $db->prepare("SELECT w.id, w.domain, w.note, w.group_id, w.created_at FROM watchlist w $where ORDER BY w.created_at DESC LIMIT ? OFFSET ?");
$stmt->execute(array_merge($params, [$perPage, $offset]));
$items = $stmt->fetchAll();

// "New domain" window (same rule as the rest of the app) + report review rules.
$defaultNewDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
$rules = reportReviewRules($db);

// Full WHOIS for the visible rows (used by the detail block).
$domainWhois = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date, creation_ts, expiration_date, registrar,
            name_servers, status, source, updated_at
        FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
    }
}

// Cached VirusTotal data for the visible rows (detail block).
$domainVt = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $vtStmt = $db->prepare("SELECT domain, verdict, malicious, suspicious, harmless, undetected,
            reputation, last_analysis_date, checked_at
        FROM domain_vt WHERE domain IN ($placeholders)");
    $vtStmt->execute($domains);
    foreach ($vtStmt->fetchAll() as $v) {
        $domainVt[$v['domain']] = $v;
    }
}

// Cached AlienVault OTX data for the visible rows (detail block).
$domainOtx = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $otxStmt = $db->prepare("SELECT domain, verdict, pulse_count, references_count, whitelisted,
            adversary, malware_families, tags, last_analysis_date, checked_at
        FROM domain_otx WHERE domain IN ($placeholders)");
    $otxStmt->execute($domains);
    foreach ($otxStmt->fetchAll() as $o) {
        $domainOtx[$o['domain']] = $o;
    }
}

// Load domain tags
$domainTags = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $tagStmt = $db->prepare("SELECT domain, tag, note FROM domain_tags WHERE domain IN ($placeholders)");
    $tagStmt->execute($domains);
    foreach ($tagStmt->fetchAll() as $t) {
        $domainTags[$t['domain']] = $t;
    }
}

// Match context for the visible rows: all the keywords that matched each domain
// (a watchlist domain may match several) and the earliest match, used for the
// first_seen / discovered / source / historical fields of the detail block.
$domainMatches = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $mStmt = $db->prepare("SELECT m.domain, m.first_seen, m.discovered_at, m.is_historical, m.source, k.keyword
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain IN ($placeholders)
        ORDER BY m.discovered_at ASC, m.domain ASC");
    $mStmt->execute(array_merge([$userId], $domains));
    foreach ($mStmt->fetchAll() as $mrow) {
        $d = $mrow['domain'];
        if (!isset($domainMatches[$d])) {
            $domainMatches[$d] = ['keywords' => [], 'rep' => $mrow];
        }
        if (!in_array($mrow['keyword'], $domainMatches[$d]['keywords'], true)) {
            $domainMatches[$d]['keywords'][] = $mrow['keyword'];
        }
    }
}

// Count per group for badges
$groupCounts = [];
$countStmt = $db->prepare("SELECT group_id, COUNT(*) as cnt FROM watchlist WHERE user_id = ? GROUP BY group_id");
$countStmt->execute([$userId]);
foreach ($countStmt->fetchAll() as $c) {
    $groupCounts[$c['group_id'] ?? 'ungrouped'] = (int)$c['cnt'];
}
$ungroupedCount = $groupCounts['ungrouped'] ?? 0;
$totalAll = array_sum($groupCounts);

$pageTitle = 'Watchlist';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2><i class="material-icons left">star</i>Watchlist</h2>
        <span class="muted"><?= $totalAll ?> domain(s)</span>
    </div>
    <p class="muted">Private list of domains you are tracking for monitoring over time. Notes are personal and not shared with other users.</p>

    <?php if (empty($items) && empty($groups)): ?>
        <p class="muted">Your watchlist is empty. Add domains from the <a href="/notifications.php">Notifications</a> page or from any domain modal.</p>
    <?php else: ?>

        <!-- Group tabs -->
        <div class="group-tabs">
            <a href="/watchlist.php" class="group-tab <?= $groupFilter === '' || $groupFilter === '0' ? 'active' : '' ?>">Ungrouped (<?= $ungroupedCount ?>)</a>
            <?php foreach ($groups as $g): 
                $gCount = $groupCounts[(string)$g['id']] ?? 0;
                $isActive = $groupFilter === (string)$g['id'];
            ?>
                <span class="group-chip">
                    <a href="/watchlist.php?group=<?= (int)$g['id'] ?>" class="group-tab <?= $isActive ? 'active' : '' ?>"><?= htmlspecialchars($g['name']) ?> (<?= $gCount ?>)</a>
                    <form method="POST" style="margin: 0; display: inline-flex;" onsubmit="return confirm('Delete group &quot;<?= htmlspecialchars(addslashes($g['name'])) ?>&quot;? Domains will become ungrouped.')">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="delete_group">
                        <input type="hidden" name="group_id" value="<?= (int)$g['id'] ?>">
                        <button type="submit" class="group-tab group-delete" title="Delete group"><i class="material-icons tiny">close</i></button>
                    </form>
                </span>
            <?php endforeach; ?>
        </div>

        <!-- Create group form -->
        <form method="POST" class="group-create-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="create_group">
            <div class="input-field">
                <i class="material-icons prefix">create_new_folder</i>
                <input id="group_name" type="text" name="group_name" placeholder=" " required>
                <label for="group_name">New group name</label>
            </div>
            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">add</i>Add Group</button>
        </form>

        <?php if (empty($items)): ?>
            <p>No domains in this group.</p>
        <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Created</th>
                    <th>Group</th>
                    <th>Note</th>
                    <th>Added</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($items as $item):
                    $whoisRow = $domainWhois[$item['domain']] ?? null;
                    $vtRow = $domainVt[$item['domain']] ?? null;
                    $otxRow = $domainOtx[$item['domain']] ?? null;
                    $dtag = $domainTags[$item['domain']] ?? null;
                    $match = $domainMatches[$item['domain']] ?? null;

                    $creationDate = $whoisRow['creation_date'] ?? null;
                    $creationDisplay = $creationDate ? date('Y-m-d', strtotime($creationDate)) : '—';

                    $tagVal = (string)($dtag['tag'] ?? '');
                    $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];
                    $hasTag = isset($tagLabels[$tagVal]);
                    $tagCell = $hasTag
                        ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                        : '<span class="muted">&mdash;</span>';
                    $tagBadge = $hasTag ? ' ' . $tagCell : '';

                    $isNew = false;
                    if ($creationDate) {
                        $ts = strtotime($creationDate);
                        $isNew = $ts && $ts > strtotime("-{$defaultNewDays} days");
                    }

                    $ns = (!empty($whoisRow['name_servers'])) ? (json_decode((string)$whoisRow['name_servers'], true) ?: []) : [];
                    $dot = strrpos($item['domain'], '.');
                    $tld = ($dot !== false) ? substr($item['domain'], $dot + 1) : '';
                    $keywordsList = $match['keywords'] ?? [];

                    $present = [
                        'domain'             => $item['domain'],
                        'tld'                => $tld,
                        'discovered_at'      => $match['rep']['discovered_at'] ?? null,
                        'first_seen'         => $match['rep']['first_seen'] ?? null,
                        'is_historical'      => $match['rep']['is_historical'] ?? 0,
                        'source'             => $match['rep']['source'] ?? null,
                        'tag'                => $tagVal,
                        'tag_note'           => $dtag['note'] ?? null,
                        'in_watchlist'       => 1,
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
                        'otx_verdict'        => $otxRow['verdict'] ?? null,
                        'otx_pulse_count'    => $otxRow['pulse_count'] ?? null,
                        'otx_references_count' => $otxRow['references_count'] ?? null,
                        'otx_whitelisted'    => $otxRow['whitelisted'] ?? null,
                        'otx_adversary'       => $otxRow['adversary'] ?? null,
                        'otx_malware_families' => $otxRow['malware_families'] ?? null,
                        'otx_tags'           => $otxRow['tags'] ?? null,
                        'otx_last_analysis_date' => $otxRow['last_analysis_date'] ?? null,
                        'otx_checked_at'     => $otxRow['checked_at'] ?? null,
                        '_ns'                => $ns,
                        '_is_new'            => $isNew,
                    ];
                    $domainArg = htmlspecialchars(addslashes($item['domain']));
                ?>
                <tr data-domain="<?= htmlspecialchars($item['domain']) ?>">
                    <td>
                        <a href="javascript:void(0)" class="domain-link" onclick="toggleDomainDetail(this, '<?= $domainArg ?>')" aria-expanded="false"><?= htmlspecialchars($item['domain']) ?></a><?= $tagBadge ?>
                    </td>
                    <td><?= htmlspecialchars($creationDisplay) ?></td>
                    <td>
                        <form method="POST" style="margin: 0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="set_group">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <select name="group_id" class="browser-default compact" onchange="this.form.submit()">
                                <option value="" <?= $item['group_id'] === null ? 'selected' : '' ?>>— Ungrouped</option>
                                <?php foreach ($groups as $g): ?>
                                <option value="<?= (int)$g['id'] ?>" <?= $item['group_id'] == $g['id'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </form>
                    </td>
                    <td>
                        <form method="POST" style="margin: 0; display: flex; gap: 6px; align-items: center;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="update_note">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <input type="text" name="note" value="<?= htmlspecialchars($item['note'] ?? '') ?>" placeholder="Add a note..." class="browser-default compact" style="flex: 1; min-width: 120px;">
                            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">save</i>Save</button>
                        </form>
                    </td>
                    <td><?= htmlspecialchars(fmt_date($item['created_at'])) ?></td>
                    <td>
                        <form method="POST" style="margin: 0;" onsubmit="return confirm('Remove this domain from your watchlist?')">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="remove">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <button type="submit" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">delete</i>Remove</button>
                        </form>
                    </td>
                </tr>
                <tr class="domain-detail-row" data-domain="<?= htmlspecialchars($item['domain']) ?>" style="display:none;">
                    <td colspan="6"><?= renderDomainDetail($present, $keywordsList, $rules) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="pager">
            <span class="pagination-info">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> domains
            </span>
            <ul class="pagination">
                <?php if ($page > 1): ?>
                    <li class="waves-effect"><a href="/watchlist.php?page=<?= $page - 1 ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <li class="active"><a href="#!"><?= $p ?></a></li>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <li class="waves-effect"><a href="/watchlist.php?page=<?= $p ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>"><?= $p ?></a></li>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <li class="disabled"><a href="#!">…</a></li>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <li class="waves-effect"><a href="/watchlist.php?page=<?= $page + 1 ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php endif; ?>
            </ul>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
