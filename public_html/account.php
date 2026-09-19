<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$message = '';
$error = '';

// Toggle email notifications
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_email') {
    validateCsrf();
    $stmt = $db->prepare("UPDATE users SET email_notifications = NOT email_notifications WHERE id = ?");
    $stmt->execute([$userId]);
    $message = 'Email notification preference updated.';
}

// Get current preference + email
$stmt = $db->prepare("SELECT email, email_notifications FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$userId]);
$userInfo = $stmt->fetch();
$emailNotifications = (bool)($userInfo['email_notifications'] ?? false);
$userEmail = $userInfo['email'] ?? '';

$pageTitle = 'Account';
require __DIR__ . '/templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card account-card">
    <div class="card-head">
        <h2>Email notifications</h2>
    </div>
    <p class="muted">
        When enabled, you will receive an email summary each time new domains match your keywords.
    </p>
    <table class="account-info">
        <tr>
            <td class="label-col">Account email</td>
            <td class="value-col"><?= htmlspecialchars($userEmail) ?></td>
        </tr>
        <tr>
            <td class="label-col">Status</td>
            <td class="value-col">
                <?php if ($emailNotifications): ?>
                    <span class="text-success">Enabled</span>
                <?php else: ?>
                    <span class="muted">Disabled</span>
                <?php endif; ?>
            </td>
        </tr>
    </table>
    <form method="POST">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_email">
        <div class="switch">
            <label>
                Disabled
                <input type="checkbox" <?= $emailNotifications ? 'checked' : '' ?> onchange="this.form.submit()">
                <span class="lever"></span>
                Enabled
            </label>
        </div>
        <noscript>
            <button type="submit" class="btn <?= $emailNotifications ? 'btn-danger' : '' ?>">
                <?= $emailNotifications ? 'Disable notifications' : 'Enable notifications' ?>
            </button>
        </noscript>
    </form>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
