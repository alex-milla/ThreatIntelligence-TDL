<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

// Add keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add') {
    $keyword = strtolower(trim($_POST['keyword'] ?? ''));
    if (strlen($keyword) < 2) {
        $error = 'Keyword must be at least 2 characters.';
    } elseif (strlen($keyword) > 50) {
        $error = 'Keyword must be at most 50 characters.';
    } elseif (!preg_match('/^[a-z0-9\-]+$/', $keyword)) {
        $error = 'Keyword can only contain letters, numbers, and hyphens.';
    } elseif (!canAddKeyword($db, $userId)) {
        $limit = getMaxKeywords($db, $userId);
        $error = "You have reached your keyword limit ({$limit}). Contact the administrator.";
    } else {
        $stmt = $db->prepare("INSERT INTO keywords (user_id, keyword) VALUES (?, ?)");
        try {
            $stmt->execute([$userId, $keyword]);
            $message = 'Keyword added successfully.';
        } catch (PDOException $e) {
            $error = 'This keyword already exists in your list.';
        }
    }
}

// Delete keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    validateCsrf();
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $stmt = $db->prepare("DELETE FROM keywords WHERE id = ? AND user_id = ?");
    $stmt->execute([$keywordId, $userId]);
    $message = 'Keyword deleted.';
}

// Admin recheck
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'recheck_keywords') {
    validateCsrf();
    if ($isAdmin) {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['recheck_keywords', '']);
        $message = 'Keyword recheck queued. The worker will scan all cached domains against current keywords.';
    } else {
        $error = 'Only administrators can trigger a recheck.';
    }
}

// List keywords
$stmt = $db->prepare("SELECT id, keyword, match_count, created_at FROM keywords WHERE user_id = ? ORDER BY created_at DESC");
$stmt->execute([$userId]);
$keywords = $stmt->fetchAll();

// Recheck status for admin stop button
$recheckStatus = null;
$recheckRunning = false;
if ($isAdmin) {
    $recheckStatus = $db->query("SELECT * FROM recheck_status WHERE id = 1")->fetch();
    $recheckRunning = !empty($recheckStatus['is_running']);
}

$pageTitle = 'My Keywords';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <h2>My Keywords</h2>
    
    <?php if ($message): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    
    <form method="POST" style="display: flex; gap: 10px; margin-bottom: 20px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="add">
        <input type="text" name="keyword" placeholder="e.g. santander, nasa, caixabank" required style="flex: 1;">
        <button type="submit" class="btn">Add Keyword</button>
    </form>
    
    <?php if ($isAdmin): ?>
    <div style="margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
        <form method="POST" style="margin: 0;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <button type="submit" class="btn btn-danger btn-small" <?= $recheckRunning ? 'disabled' : '' ?>>
                <?= $recheckRunning ? '🔍 Recheck in progress...' : '🔍 Recheck All Cached Domains' ?>
            </button>
        </form>
        <?php if ($recheckRunning): ?>
        <form method="POST" style="margin: 0;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="stop_recheck">
            <button type="submit" class="btn btn-danger btn-small">⏹ Stop Recheck</button>
        </form>
        <?php endif; ?>
        <span style="color: #666; font-size: 0.85rem;">Scans all previously downloaded domains against current keywords (admin only)</span>
    </div>
    <?php endif; ?>
    
    <?php if (empty($keywords)): ?>
        <p>No keywords yet. Add your first keyword above.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Keyword</th>
                    <th>Matches</th>
                    <th>Added</th>
                    <th style="width: 100px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($keywords as $k): ?>
                <tr>
                    <td><?= htmlspecialchars($k['keyword']) ?></td>
                    <td><a href="/notifications.php?q=<?= urlencode($k['keyword']) ?>"><?= (int)$k['match_count'] ?></a></td>
                    <td><?= htmlspecialchars($k['created_at']) ?></td>
                    <td>
                        <form method="POST" style="display: inline;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                            <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Delete this keyword?')">Delete</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
