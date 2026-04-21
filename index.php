<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);

// Toggle email notifications
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_email') {
    validateCsrf();
    $stmt = $db->prepare("UPDATE users SET email_notifications = NOT email_notifications WHERE id = ?");
    $stmt->execute([$userId]);
    header('Location: /');
    exit;
}

// Get current preference
$stmt = $db->prepare("SELECT email_notifications FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$userId]);
$emailNotifications = (bool)$stmt->fetchColumn();

// Stats
$stmt = $db->prepare("SELECT COUNT(*) FROM keywords WHERE user_id = ?");
$stmt->execute([$userId]);
$keywordCount = (int)$stmt->fetchColumn();

$stmt = $db->prepare("SELECT COUNT(*) FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ?");
$stmt->execute([$userId]);
$matchCount = (int)$stmt->fetchColumn();

$stmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
$stmt->execute([$userId]);
$unreadCount = (int)$stmt->fetchColumn();

// Recent matches
$stmt = $db->prepare("SELECT m.id, m.domain, m.tld, m.discovered_at, k.keyword 
    FROM matches m 
    JOIN keywords k ON m.keyword_id = k.id 
    WHERE k.user_id = ? 
    ORDER BY m.discovered_at DESC 
    LIMIT 20");
$stmt->execute([$userId]);
$recentMatches = $stmt->fetchAll();

$pageTitle = 'Dashboard';
require __DIR__ . '/templates/header.php';
?>

<div class="stats">
    <div class="stat-box">
        <div class="number"><?= $keywordCount ?></div>
        <div class="label">Keywords</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $matchCount ?></div>
        <div class="label">Total Matches</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $unreadCount ?></div>
        <div class="label">Unread Notifications</div>
    </div>
</div>

<div class="card">
    <h2>Recent Matches</h2>
    <?php if (empty($recentMatches)): ?>
        <p>No matches yet. Start by adding <a href="/keywords.php">keywords</a>.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>TLD</th>
                    <th>Keyword</th>
                    <th>Discovered</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentMatches as $m): ?>
                <tr>
                    <td><?= htmlspecialchars($m['domain']) ?></td>
                    <td><?= htmlspecialchars($m['tld']) ?></td>
                    <td><?= htmlspecialchars($m['keyword']) ?></td>
                    <td><?= htmlspecialchars($m['discovered_at']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card">
    <h2>Email Notifications</h2>
    <p>Status: <strong><?= $emailNotifications ? 'Enabled' : 'Disabled' ?></strong></p>
    <p style="color: #666; font-size: 0.9rem;">When enabled, you will receive an email summary each time new domains match your keywords.</p>
    <form method="POST" style="margin-top: 10px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_email">
        <button type="submit" class="btn btn-small <?= $emailNotifications ? 'btn-danger' : '' ?>"><?= $emailNotifications ? 'Disable' : 'Enable' ?></button>
    </form>
</div>

<?php if ($isAdmin): ?>
<div class="card">
    <h2>Admin — Last Sync</h2>
    <?php
    $stmt = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 5");
    $logs = $stmt->fetchAll();
    $workerStatus = $db->query("SELECT * FROM worker_status WHERE id = 1")->fetch();
    ?>
    <?php if ($workerStatus): ?>
    <div class="stats" style="margin-bottom: 15px;">
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['tlds_processed'] ?? 0) ?></div>
            <div class="label">TLDs Processed</div>
        </div>
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['domains_processed'] ?? 0) ?></div>
            <div class="label">Domains Processed</div>
        </div>
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['matches_found'] ?? 0) ?></div>
            <div class="label">Matches Found</div>
        </div>
    </div>
    <?php endif; ?>
    <?php if (empty($logs)): ?>
        <p>No sync logs yet.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr><th>Time</th><th>Received</th><th>Inserted</th><th>Error</th></tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                <tr>
                    <td><?= htmlspecialchars($log['created_at']) ?></td>
                    <td><?= (int)$log['records_received'] ?></td>
                    <td><?= (int)$log['records_inserted'] ?></td>
                    <td><?= htmlspecialchars($log['error'] ?? '-') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p style="margin-top: 10px;"><a href="/admin/" class="btn">Admin Panel</a></p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php require __DIR__ . '/templates/footer.php'; ?>
