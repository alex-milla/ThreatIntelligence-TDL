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

// Delete all notifications
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_all') {
    $db->prepare("DELETE FROM notifications WHERE user_id = ?")->execute([$userId]);
    header('Location: /notifications.php');
    exit;
}

// Search / filter params
$search = trim($_GET['q'] ?? '');
$unreadOnly = isset($_GET['unread_only']) && $_GET['unread_only'] === '1';
$dateFilter = $_GET['date'] ?? 'all';
$validDateFilters = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];

$sql = "SELECT n.id, n.is_read, n.created_at, m.domain, m.tld, m.discovered_at, k.keyword 
    FROM notifications n 
    JOIN matches m ON n.match_id = m.id 
    JOIN keywords k ON m.keyword_id = k.id 
    WHERE n.user_id = ?";
$params = [$userId];

if ($search !== '') {
    $sql .= " AND (m.domain LIKE ? OR m.tld LIKE ? OR k.keyword LIKE ?)";
    $like = '%' . $search . '%';
    $params[] = $like;
    $params[] = $like;
    $params[] = $like;
}

if ($unreadOnly) {
    $sql .= " AND n.is_read = 0";
}

if (!empty($validDateFilters[$dateFilter])) {
    $sql .= " AND m.discovered_at >= datetime('now', ?)";
    $params[] = $validDateFilters[$dateFilter];
}

$sql .= " ORDER BY n.created_at DESC LIMIT 100";
$stmt = $db->prepare($sql);
$stmt->execute($params);
$notifications = $stmt->fetchAll();

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
            <form method="POST" style="margin: 0;" onsubmit="return confirm('Delete ALL notifications? This cannot be undone.');">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="delete_all">
                <button type="submit" class="btn btn-small btn-danger">Delete All</button>
            </form>
        </div>
        <?php endif; ?>
    </div>

    <form method="GET" style="margin: 15px 0; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
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
    
    <?php if (empty($notifications)): ?>
        <p>No notifications yet. Matches will appear here when the worker finds new domains.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Domain</th>
                    <th>TLD</th>
                    <th>Keyword</th>
                    <th>Discovered</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($notifications as $n): ?>
                <tr class="<?= $n['is_read'] ? '' : 'unread' ?>">
                    <td><?= $n['is_read'] ? 'Read' : '<strong>Unread</strong>' ?></td>
                    <td><?= htmlspecialchars($n['domain']) ?></td>
                    <td><?= htmlspecialchars($n['tld']) ?></td>
                    <td><?= htmlspecialchars($n['keyword']) ?></td>
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
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
