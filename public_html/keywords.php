<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

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

// Admin stop recheck
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'stop_recheck') {
    validateCsrf();
    if ($isAdmin) {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['stop_recheck', '']);
        $_SESSION['flash_message'] = 'Stop recheck queued. The worker will stop at the next batch boundary.';
    } else {
        $_SESSION['flash_error'] = 'Only administrators can stop a recheck.';
    }
    header('Location: /keywords.php');
    exit;
}

// List keywords with visible match count:
// only matches that still have an active notification for this user
// and are not in the user's watchlist
$stmt = $db->prepare("SELECT k.id, k.keyword, k.match_count, k.created_at,
    (SELECT COUNT(*) FROM matches m WHERE m.keyword_id = k.id
     AND EXISTS (SELECT 1 FROM notifications n WHERE n.match_id = m.id AND n.user_id = ?)
     AND NOT EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain)
    ) AS visible_count
FROM keywords k
WHERE k.user_id = ?
ORDER BY k.created_at DESC");
$stmt->execute([$userId, $userId, $userId]);
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
    <div class="card-head">
        <h2>My Keywords</h2>
        <span class="muted"><?= count($keywords) ?> keyword(s)</span>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST" class="keyword-add-form">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="add">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="keyword" type="text" name="keyword" class="validate" placeholder=" " required>
            <label for="keyword">Keyword</label>
            <span class="helper-text">e.g. santander, nasa, caixabank</span>
        </div>
        <button type="submit" class="btn waves-effect"><i class="material-icons left">add</i>Add Keyword</button>
    </form>

    <?php if ($isAdmin): ?>
    <div class="section-actions">
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <button type="submit" class="btn btn-outline waves-effect" <?= $recheckRunning ? 'disabled' : '' ?>>
                <i class="material-icons left">search</i><?= $recheckRunning ? 'Recheck in progress...' : 'Recheck All Cached Domains' ?>
            </button>
        </form>
        <?php if ($recheckRunning): ?>
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="stop_recheck">
            <button type="submit" class="btn waves-effect btn-danger"><i class="material-icons left">stop</i>Stop Recheck</button>
        </form>
        <?php endif; ?>
        <span class="muted">Scans all previously downloaded domains against current keywords (admin only)</span>
    </div>
    <?php endif; ?>

    <?php if (empty($keywords)): ?>
        <p class="muted">No keywords yet. Add your first keyword above.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
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
                    <td><strong><?= htmlspecialchars($k['keyword']) ?></strong></td>
                    <td><a href="/notifications.php?q=<?= urlencode($k['keyword']) ?>"><?= (int)$k['visible_count'] ?></a><?php if ((int)$k['visible_count'] !== (int)$k['match_count']): ?> <span class="muted">(<?= (int)$k['match_count'] ?> total)</span><?php endif; ?></td>
                    <td><?= htmlspecialchars(fmt_date($k['created_at'])) ?></td>
                    <td>
                        <form method="POST" style="display: inline;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Delete this keyword?')"><i class="material-icons left">delete</i>Delete</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
