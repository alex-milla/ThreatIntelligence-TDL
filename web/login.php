<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

if (!empty($_SESSION['user_id'])) {
    header('Location: /');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    $db = Database::get();
    $ip = getClientIp();
    
    if (isRateLimited($db, $ip)) {
        $error = 'Too many failed attempts. Please try again in 15 minutes.';
    } else {
        $stmt = $db->prepare("SELECT id, username, password_hash, is_admin FROM users WHERE username = ? AND is_active = 1 LIMIT 1");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password_hash'])) {
            clearLoginAttempts($db, $ip);
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            header('Location: /');
            exit;
        } else {
            recordLoginAttempt($db, $ip, $username);
            $error = 'Invalid username or password.';
        }
    }
}

$pageTitle = 'Login';
require __DIR__ . '/templates/header.php';
?>

<div class="card" style="max-width: 400px; margin: 60px auto;">
    <h2>Login</h2>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="POST">
        <?php csrfField(); ?>
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required autofocus>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>
    <p style="margin-top: 15px;"><a href="/register.php">Create an account</a></p>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
