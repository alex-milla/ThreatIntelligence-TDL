<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

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
    $delWhere = "WHERE n.user_id = ?";
    $delParams = [$userId];
    $qFilter = trim($_POST['q'] ?? '');
    $dateFilterPost = $_POST['date'] ?? 'all';
    $unreadFilterPost = isset($_POST['unread_only']) && $_POST['unread_only'] === '1';

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

    $db->prepare("DELETE FROM notifications WHERE id IN (SELECT n.id FROM notifications n JOIN matches m ON n.match_id = m.id JOIN keywords k ON m.keyword_id = k.id $delWhere)")->execute($delParams);

    $redirect = '/notifications.php';
    if ($qFilter !== '' || $dateFilterPost !== 'all' || $unreadFilterPost) {
        $qs = [];
        if ($qFilter !== '') $qs['q'] = $qFilter;
        if ($dateFilterPost !== 'all') $qs['date'] = $dateFilterPost;
        if ($unreadFilterPost) $qs['unread_only'] = '1';
        $redirect .= '?' . http_build_query($qs);
    }
    header('Location: ' . $redirect);
    exit;
}

// Search / filter params
$search = trim($_GET['q'] ?? '');
$unreadOnly = isset($_GET['unread_only']) && $_GET['unread_only'] === '1';
$dateFilter = $_GET['date'] ?? 'all';
$validDateFilters = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];

// Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;
$offset = ($page - 1) * $perPage;

$where = "WHERE n.user_id = ?";
$params = [$userId];

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
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

// Fetch page
$sql = "SELECT n.id, n.is_read, n.created_at, m.domain, m.tld, m.discovered_at, m.first_seen, k.keyword 
    FROM notifications n 
    JOIN matches m ON n.match_id = m.id 
    JOIN keywords k ON m.keyword_id = k.id 
    $where 
    ORDER BY n.created_at DESC 
    LIMIT $perPage OFFSET $offset";
$stmt = $db->prepare($sql);
$stmt->execute($params);
$notifications = $stmt->fetchAll();

// Helper to build pagination URLs preserving filters
function notifUrl(int $p, string $search, string $date, bool $unread): string {
    $q = ['page' => $p];
    if ($search !== '') $q['q'] = $search;
    if ($date !== 'all') $q['date'] = $date;
    if ($unread) $q['unread_only'] = '1';
    return '/notifications.php?' . http_build_query($q);
}

$pageTitle = 'Notifications';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>Notifications</h2>
        <?php if (!empty($notifications)): ?>
        <div style="display: flex; gap: 10px;">
            <form method="POST" style="margin: 0;">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="mark_all_read">
                <button type="submit" class="btn btn-small">Mark All Read</button>
            </form>
        </div>
        <?php endif; ?>
    </div>

    <form method="GET" id="filter-form" style="margin: 15px 0; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
        <input type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder="Search domain, TLD or keyword..." style="flex: 1; min-width: 200px; padding: 8px;">
        <select name="date" style="padding: 8px;">
            <option value="all" <?= $dateFilter === 'all' ? 'selected' : '' ?>>All time</option>
            <option value="24h" <?= $dateFilter === '24h' ? 'selected' : '' ?>>Last 24h</option>
            <option value="7d" <?= $dateFilter === '7d' ? 'selected' : '' ?>>Last 7 days</option>
            <option value="30d" <?= $dateFilter === '30d' ? 'selected' : '' ?>>Last 30 days</option>
        </select>
        <label style="display: flex; align-items: center; gap: 5px; white-space: nowrap;">
            <input type="checkbox" name="unread_only" value="1" <?= $unreadOnly ? 'checked' : '' ?>>
            Unread only
        </label>
        <button type="submit" class="btn btn-small">Search</button>
        <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all'): ?>
        <a href="/notifications.php" class="btn btn-small btn-danger">Clear</a>
        <?php endif; ?>
    </form>

    <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all'): ?>
    <form method="POST" style="margin-bottom: 15px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="delete_all_matching">
        <input type="hidden" name="q" value="<?= htmlspecialchars($search) ?>">
        <input type="hidden" name="date" value="<?= htmlspecialchars($dateFilter) ?>">
        <input type="hidden" name="unread_only" value="<?= $unreadOnly ? '1' : '0' ?>">
        <button type="submit" class="btn btn-danger" onclick="return confirm('This will delete ALL <?= $total ?> notification(s) matching your current filter across every page. This cannot be undone. Are you sure?')">Delete All Matching Results (<?= $total ?>)</button>
    </form>
    <?php endif; ?>
    
    <?php if (empty($notifications)): ?>
        <p>No notifications yet. Matches will appear here when the worker finds new domains.</p>
    <?php else: ?>
        <form method="POST" id="bulk-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="delete_selected">
            <div style="margin-bottom: 10px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                <label style="display: inline-flex; align-items: center; gap: 5px; cursor: pointer;">
                    <input type="checkbox" id="select-all"> <strong>Select all visible</strong>
                </label>
                <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Delete selected notifications?')">Delete Selected</button>
                <?php if ($search !== '' || $unreadOnly || $dateFilter !== 'all'): ?>
                <button type="submit" formaction="/notifications.php" formmethod="POST" class="btn btn-small btn-danger" name="action" value="delete_all_matching" onclick="return confirm('This will delete ALL <?= $total ?> notification(s) matching your current filter across every page. This cannot be undone. Are you sure?')">Delete All Matching (<?= $total ?>)</button>
                <?php endif; ?>
            </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 30px;"></th>
                    <th>Status</th>
                    <th>Domain</th>
                    <th>TLD</th>
                    <th>Keyword</th>
                    <th>First Seen</th>
                    <th>Discovered</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($notifications as $n): ?>
                <tr class="<?= $n['is_read'] ? '' : 'unread' ?>">
                    <td><input type="checkbox" name="selected[]" value="<?= (int)$n['id'] ?>" class="row-check"></td>
                    <td><?= $n['is_read'] ? 'Read' : '<strong>Unread</strong>' ?></td>
                    <td><a href="javascript:void(0)" onclick="openDomainModal('<?= htmlspecialchars(addslashes($n['domain'])) ?>')" style="color: #3498db; text-decoration: underline; cursor: pointer;"><?= htmlspecialchars($n['domain']) ?></a></td>
                    <td><?= htmlspecialchars($n['tld']) ?></td>
                    <td><?= htmlspecialchars($n['keyword']) ?></td>
                    <td><?= htmlspecialchars($n['first_seen'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($n['discovered_at']) ?></td>
                    <td>
                        <form method="POST" style="display: inline;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="notif_id" value="<?= (int)$n['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Delete this notification?')">Delete</button>
                        </form>
                        <?php if (!$n['is_read']): ?>
                        <form method="POST" style="display: inline;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="mark_read">
                            <input type="hidden" name="notif_id" value="<?= (int)$n['id'] ?>">
                            <button type="submit" class="btn btn-small">Mark Read</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </form>

        <div style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <span style="color: #666; font-size: 0.9rem;">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> notifications
            </span>
            <div style="display: flex; gap: 5px; flex-wrap: wrap;">
                <?php if ($page > 1): ?>
                    <a href="<?= htmlspecialchars(notifUrl($page - 1, $search, $dateFilter, $unreadOnly)) ?>" class="btn btn-small">« Previous</a>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <span class="btn btn-small" style="background: #3498db; color: white; cursor: default;"><?= $p ?></span>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <a href="<?= htmlspecialchars(notifUrl($p, $search, $dateFilter, $unreadOnly)) ?>" class="btn btn-small"><?= $p ?></a>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <span style="padding: 5px;">…</span>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="<?= htmlspecialchars(notifUrl($page + 1, $search, $dateFilter, $unreadOnly)) ?>" class="btn btn-small">Next »</a>
                <?php endif; ?>
            </div>
        </div>

        <script>
        document.getElementById('select-all').addEventListener('change', function(e) {
            document.querySelectorAll('.row-check').forEach(cb => cb.checked = e.target.checked);
        });
        </script>
    <?php endif; ?>
</div>

<!-- Domain detail modal -->
<div id="domain-modal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center;">
    <div style="background: white; padding: 25px; border-radius: 8px; max-width: 520px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-height: 90vh; overflow-y: auto;">
        <h3 id="modal-domain-title" style="margin-top: 0; word-break: break-all;"></h3>
        <div id="modal-whois-loading" style="color: #666; font-size: 0.9rem; margin: 15px 0;">Loading whois data...</div>
        <div id="modal-whois-content" style="display: none; margin: 15px 0;">
            <table style="width: 100%; font-size: 0.9rem;">
                <tr><td style="color: #666; padding: 4px 8px 4px 0;">Creation Date</td><td id="modal-creation" style="font-weight: 600;"></td></tr>
                <tr><td style="color: #666; padding: 4px 8px 4px 0;">Expiration Date</td><td id="modal-expiration" style="font-weight: 600;"></td></tr>
                <tr><td style="color: #666; padding: 4px 8px 4px 0;">Registrar</td><td id="modal-registrar" style="font-weight: 600;"></td></tr>
                <tr><td style="color: #666; padding: 4px 8px 4px 0; vertical-align: top;">Name Servers</td><td id="modal-ns" style="font-weight: 600;"></td></tr>
            </table>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 15px;">
            <a id="modal-vt" href="#" target="_blank" class="btn" style="text-align: center; background: #3949ab;">🛡️ Open in VirusTotal</a>
        </div>
        <button onclick="document.getElementById('domain-modal').style.display='none'" class="btn btn-danger" style="margin-top: 15px; width: 100%;">Close</button>
    </div>
</div>

<script>
function openDomainModal(domain) {
    document.getElementById('modal-domain-title').textContent = domain;
    document.getElementById('modal-vt').href = 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain);
    document.getElementById('modal-whois-loading').style.display = 'block';
    document.getElementById('modal-whois-content').style.display = 'none';
    document.getElementById('domain-modal').style.display = 'flex';

    fetch('/ajax_whois.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            document.getElementById('modal-whois-loading').style.display = 'none';
            if (data.success) {
                document.getElementById('modal-creation').textContent = data.creationDate ? new Date(data.creationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-expiration').textContent = data.expirationDate ? new Date(data.expirationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-registrar').textContent = data.registrar || 'N/A';
                document.getElementById('modal-ns').innerHTML = data.nameServers.length ? data.nameServers.map(ns => '<div>' + ns + '</div>').join('') : 'N/A';
                document.getElementById('modal-whois-content').style.display = 'block';
            } else {
                document.getElementById('modal-whois-loading').textContent = 'Whois unavailable: ' + (data.error || 'Unknown error');
            }
        })
        .catch(() => {
            document.getElementById('modal-whois-loading').textContent = 'Whois query failed. Try again later.';
        });
}
document.getElementById('domain-modal').addEventListener('click', function(e) {
    if (e.target === this) this.style.display = 'none';
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
