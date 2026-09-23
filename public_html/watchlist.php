<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
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

// Load whois for visible rows
$domainWhois = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
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
                    $whois = $domainWhois[$item['domain']] ?? null;
                    $creationDate = $whois['creation_date'] ?? null;
                    $creationDisplay = $creationDate ? date('Y-m-d', strtotime($creationDate)) : '—';
                    $dtag = $domainTags[$item['domain']] ?? null;
                    $tagBadge = '';
                    if ($dtag) {
                        $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];
                        $tagVal = $dtag['tag'];
                        $cls = in_array($tagVal, ['good', 'bad', 'observing'], true) ? $tagVal : 'bad';
                        $tagBadge = ' <span class="tag-chip ' . $cls . '">' . ($tagLabels[$tagVal] ?? strtoupper($tagVal)) . '</span>';
                    }
                ?>
                <tr data-domain="<?= htmlspecialchars($item['domain']) ?>">
                    <td>
                        <a href="javascript:void(0)" class="domain-link" onclick="toggleDomainDetail(this, '<?= htmlspecialchars(addslashes($item['domain'])) ?>')"><?= htmlspecialchars($item['domain']) ?></a><?= $tagBadge ?>
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
                            <button type="submit" class="btn btn-small btn-danger waves-effect"><i class="material-icons left">delete</i>Remove</button>
                        </form>
                    </td>
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

<script>
let _modalDomain = '';
function buildPanelHtml(domain) {
    return '<div class="dpanel">'
        + '<div class="dpanel-header">'
        +   '<h3 id="modal-domain-title"></h3>'
        +   '<button type="button" class="dpanel-close" aria-label="Close panel" onclick="closeDomainDetail()"><i class="material-icons">close</i></button>'
        + '</div>'
        + '<div class="dpanel-section">'
        +   '<div class="dpanel-section-label">WHOIS Registry Data</div>'
        +   '<button type="button" id="modal-whois-btn" class="btn btn-small waves-effect" style="width:100%; margin-bottom:8px;" onclick="fetchWhois()">Fetch WHOIS via worker</button>'
        +   '<div id="modal-whois-loading" class="muted" style="display:none; padding:4px 0;">Consultando WHOIS...</div>'
        +   '<div id="modal-whois-content" style="display:none;">'
        +     '<div class="dpanel-whois-grid">'
        +       '<div>Creation Date</div><div id="modal-creation"></div>'
        +       '<div>Expiration Date</div><div id="modal-expiration"></div>'
        +       '<div>Registrar</div><div id="modal-registrar"></div>'
        +       '<div>Name Servers</div><div id="modal-ns"></div>'
        +       '<div>First Seen (zone)</div><div id="modal-first-seen"></div>'
        +     '</div>'
        +   '</div>'
        +   '<div id="modal-whois-status" class="muted" style="display:none; padding:4px 0;"></div>'
        +   '<div id="modal-whois-error" class="text-danger" style="display:none; padding:4px 0;"></div>'
        + '</div>'
        + '<div class="dpanel-section" id="modal-tag-box">'
        +   '<div class="dpanel-section-label">Classification</div>'
        +   '<div class="dpanel-status-row"><span class="muted">Status:</span><span class="status-value" id="modal-tag-current">Loading...</span></div>'
        +   '<div class="dpanel-btn-row">'
        +     '<button type="button" class="btn btn-small btn-outline good waves-effect" onclick="tagDomain(_modalDomain, \'good\')">Mark Good</button>'
        +     '<button type="button" class="btn btn-small btn-outline bad waves-effect" onclick="tagDomain(_modalDomain, \'bad\')">Mark Bad</button>'
        +     '<button type="button" class="btn btn-small btn-outline warning waves-effect" onclick="tagDomain(_modalDomain, \'observing\')"><i class="material-icons left">help_outline</i>Insufficient info</button>'
        +     '<button type="button" class="btn btn-small btn-danger waves-effect" onclick="tagDomain(_modalDomain, \'\')">Clear</button>'
        +   '</div>'
        + '</div>'
        + '<div class="dpanel-section" id="modal-watchlist-box">'
        +   '<div class="dpanel-section-label">Watchlist</div>'
        +   '<div class="dpanel-status-row"><span class="muted">Status:</span><span class="status-value" id="modal-watchlist-current">Loading...</span></div>'
        +   '<div class="dpanel-btn-row"><button type="button" id="modal-watchlist-btn" class="btn btn-small waves-effect" onclick="toggleWatchlist(_modalDomain)">Remove from Watchlist</button></div>'
        + '</div>'
        + '<div class="dpanel-section" id="modal-vt-box">'
        +   '<div class="dpanel-section-label">VirusTotal</div>'
        +   '<div class="status-value" id="modal-vt-verdict">Not checked</div>'
        +   '<div class="dpanel-btn-row"><button type="button" class="btn btn-small waves-effect" onclick="checkVt()">Check VirusTotal</button></div>'
        +   '<div id="modal-vt-error" class="text-danger" style="display:none; padding:4px 0;"></div>'
        + '</div>'
        + '<div class="dpanel-footer"><a id="modal-vt" href="#" target="_blank" class="btn btn-outline info waves-effect"><i class="material-icons left">shield</i>Open in VirusTotal</a></div>'
        + '</div>';
}
function toggleDomainDetail(linkEl, domain) {
    var row = linkEl.closest('tr');
    var existing = row.nextElementSibling;
    if (existing && existing.classList.contains('dpanel-row') && existing.dataset.domain === domain) {
        existing.remove();
        return;
    }
    document.querySelectorAll('.dpanel-row').forEach(function(r) { r.remove(); });
    _modalDomain = domain;
    var detailRow = document.createElement('tr');
    detailRow.className = 'dpanel-row';
    detailRow.dataset.domain = domain;
    detailRow.innerHTML = '<td colspan="6">' + buildPanelHtml(domain) + '</td>';
    row.parentNode.insertBefore(detailRow, row.nextSibling);
    document.getElementById('modal-domain-title').textContent = domain;
    document.getElementById('modal-vt').href = 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain);
    loadCachedWhois();
    loadDomainTag(domain);
    loadWatchlistStatus(domain);
    loadVtStatus();
    detailRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}
function closeDomainDetail() {
    document.querySelectorAll('.dpanel-row').forEach(function(r) { r.remove(); });
}
function loadDomainTag(domain) {
    fetch('/ajax_tag_domain.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-tag-current');
            if (!box) return;
            if (data.success && data.tag) {
                const tag = data.tag.tag;
                const cls = tag === 'good' ? 'tag-good-text' : (tag === 'observing' ? 'tag-observing-text' : 'tag-bad-text');
                const label = tag === 'observing' ? 'OBSERVING (insufficient info)' : tag.toUpperCase();
                box.innerHTML = '<span class="' + cls + '">' + label + '</span>';
                if (data.tag.note) box.innerHTML += ' &mdash; ' + htmlspecialchars(data.tag.note);
            } else {
                box.textContent = 'Not classified';
            }
        })
        .catch(() => {
            const box = document.getElementById('modal-tag-current');
            if (box) box.textContent = 'Unable to load tag';
        });
}
function loadWatchlistStatus(domain) {
    fetch('/ajax_watchlist.php?check=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-watchlist-current');
            const btn = document.getElementById('modal-watchlist-btn');
            if (!box) return;
            if (data.in_watchlist) {
                let html = '<span class="text-in-watchlist">In watchlist</span>';
                if (data.group_name) html += ' <span class="text-soft">(' + htmlspecialchars(data.group_name) + ')</span>';
                if (data.note) html += ' &mdash; ' + htmlspecialchars(data.note);
                box.innerHTML = html;
                btn.textContent = 'Remove from Watchlist';
                btn.classList.add('btn-danger');
            } else {
                box.textContent = 'Not in watchlist';
                btn.textContent = 'Add to Watchlist';
                btn.classList.remove('btn-danger');
            }
        })
        .catch(() => {
            const box = document.getElementById('modal-watchlist-current');
            if (box) box.textContent = 'Unable to load watchlist status';
        });
}
function toggleWatchlist(domain) {
    fetch('/ajax_watchlist.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            // The domain's watchlist membership changed, so refresh the list.
            window.location.reload();
        } else {
            alert(data.error || 'Failed to update watchlist');
        }
    })
    .catch(() => alert('Failed to update watchlist'));
}
function tagDomain(domain, tag) {
    fetch('/ajax_tag_domain.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain, tag: tag})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            loadDomainTag(domain);
            window.location.reload();
        } else {
            alert(data.error || 'Failed to tag domain');
        }
    })
    .catch(() => alert('Failed to tag domain'));
}
function htmlspecialchars(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
