<?php
require __DIR__ . '/includes/db.php';
require __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

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

// Fetch notifications with match details
$stmt = $db->prepare("SELECT n.id, n.is_read, n.created_at, m.domain, m.tld, m.discovered_at, k.keyword 
    FROM notifications n 
    JOIN matches m ON n.match_id = m.id 
    JOIN keywords k ON m.keyword_id = k.id 
    WHERE n.user_id = ? 
    ORDER BY n.created_at DESC 
    LIMIT 100");
$stmt->execute([$userId]);
$notifications = $stmt->fetchAll();

$pageTitle = 'Notifications';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>Notifications</h2>
        <?php if (!empty($notifications)): ?>
        <form method="POST" style="margin: 0;">
            <input type="hidden" name="action" value="mark_all_read">
            <button type="submit" class="btn btn-small">Mark All Read</button>
        </form>
        <?php endif; ?>
    </div>
    
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
                        <?php if (!$n['is_read']): ?>
                        <form method="POST" style="display: inline;">
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
