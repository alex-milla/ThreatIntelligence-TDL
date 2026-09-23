<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
sendSecurityHeaders();

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

$assetVersion = is_file(__DIR__ . '/VERSION') ? trim((string)file_get_contents(__DIR__ . '/VERSION')) : '0';
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f97316">
    <title>Sign in - ThreatIntelligence-TDL</title>
    <script>
    (function () {
        try {
            var t = localStorage.getItem('tdl-theme');
            if (t !== 'dark' && t !== 'light') { t = 'light'; }
            document.documentElement.setAttribute('data-theme', t);
        } catch (e) {
            document.documentElement.setAttribute('data-theme', 'light');
        }
    })();
    </script>
    <link rel="stylesheet" href="/css/fonts.css?v=<?= urlencode($assetVersion) ?>">
    <link rel="stylesheet" href="/css/app.css?v=<?= urlencode($assetVersion) ?>">
</head>
<body>
    <div class="login-page">
        <div class="login-wrap">
            <div class="login-brand">
                <div class="login-logo"><i class="material-icons">shield</i></div>
                <h1 class="login-title">ThreatIntelligence-TDL</h1>
                <p class="login-subtitle">Domain threat monitoring</p>
            </div>

            <form method="POST" class="login-card" id="login-form">
                <?php csrfField(); ?>
                <div class="login-field">
                    <label class="login-label" for="username">Username</label>
                    <input class="login-input" id="username" type="text" name="username" required autofocus autocomplete="username">
                </div>
                <div class="login-field">
                    <label class="login-label" for="password">Password</label>
                    <input class="login-input" id="password" type="password" name="password" required autocomplete="current-password">
                </div>
                <?php if ($error): ?>
                    <div class="login-error" role="alert"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                <button type="submit" class="login-btn" id="login-submit">Sign in</button>
            </form>

            <p class="login-alt">Don't have an account? <a href="/register.php">Create one</a></p>
        </div>
    </div>
    <script>
    (function () {
        var form = document.getElementById('login-form');
        if (!form) return;
        form.addEventListener('submit', function () {
            var btn = document.getElementById('login-submit');
            if (btn) { btn.disabled = true; btn.textContent = 'Signing in\u2026'; }
        });
    })();
    </script>
</body>
</html>
