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
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card" style="max-width: 520px;">
    <h2>Email notifications</h2>
    <p style="color: #666; font-size: 0.9rem; margin-top: 0;">
        When enabled, you will receive an email summary each time new domains match your keywords.
    </p>
    <table style="margin-top: 10px;">
        <tr>
            <td style="color: #666; width: 140px;">Account email</td>
            <td style="font-weight: 600;"><?= htmlspecialchars($userEmail) ?></td>
        </tr>
        <tr>
            <td style="color: #666;">Status</td>
            <td>
                <?php if ($emailNotifications): ?>
                    <span style="color: #27ae60; font-weight: 600;">Enabled</span>
                <?php else: ?>
                    <span style="color: #999; font-weight: 600;">Disabled</span>
                <?php endif; ?>
            </td>
        </tr>
    </table>
    <form method="POST" style="margin-top: 15px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_email">
        <button type="submit" class="btn <?= $emailNotifications ? 'btn-danger' : '' ?>">
            <?= $emailNotifications ? 'Disable notifications' : 'Enable notifications' ?>
        </button>
    </form>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
