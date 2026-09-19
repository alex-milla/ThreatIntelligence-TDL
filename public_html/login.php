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
            unset($_SESSION['csrf_token']); // force new CSRF token on fresh session
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

<div class="card auth-card">
    <div class="auth-logo">
        <i class="material-icons">security</i>
        <h2>ThreatIntelligence-TDL</h2>
    </div>
    <p class="muted">Sign in to your account</p>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="POST">
        <?php csrfField(); ?>
        <div class="input-field">
            <i class="material-icons prefix">person</i>
            <input id="username" type="text" name="username" placeholder=" " required autofocus>
            <label for="username">Username</label>
        </div>
        <div class="input-field">
            <i class="material-icons prefix">lock</i>
            <input id="password" type="password" name="password" placeholder=" " required>
            <label for="password">Password</label>
        </div>
        <button type="submit" class="btn waves-effect" style="width:100%;"><i class="material-icons left">login</i>Login</button>
    </form>
    <p style="margin-top: 16px;">Don't have an account? <a href="/register.php">Create one</a></p>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
