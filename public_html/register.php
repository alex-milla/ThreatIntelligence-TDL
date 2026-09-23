<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
sendSecurityHeaders();

if (!empty($_SESSION['user_id'])) {
    header('Location: /');
    exit;
}

$db = Database::get();
$registrationClosed = !isRegistrationOpen($db);

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($registrationClosed) {
        http_response_code(403);
        $error = 'Registration is currently closed.';
    } else {
        validateCsrf();
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (strlen($username) < 3 || strlen($username) > 30 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $error = 'Username must be 3-30 characters and contain only letters, numbers, and underscores.';
        } elseif (strlen($password) < 8 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Password must be at least 8 characters and email must be valid.';
        } else {
            $db = Database::get();
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, max_keywords) VALUES (?, ?, ?, ?)");
            try {
                $stmt->execute([$username, $email, $hash, DEFAULT_MAX_KEYWORDS]);
                header('Location: /login.php?registered=1');
                exit;
            } catch (PDOException $e) {
                if (strpos($e->getMessage(), 'UNIQUE constraint failed') !== false) {
                    $error = 'Username or email already exists.';
                } else {
                    $error = 'Registration failed. Please try again.';
                }
            }
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
    <title>Create account - ThreatIntelligence-TDL</title>
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
                <p class="login-subtitle">Create your account</p>
            </div>

            <form method="POST" class="login-card" id="register-form">
                <?php csrfField(); ?>
                <?php if ($registrationClosed): ?>
                    <div class="login-error" role="alert">Registration is currently closed. Contact the administrator.</div>
                <?php else: ?>
                    <div class="login-field">
                        <label class="login-label" for="username">Username</label>
                        <input class="login-input" id="username" type="text" name="username" required minlength="3" maxlength="30" autofocus autocomplete="username">
                    </div>
                    <div class="login-field">
                        <label class="login-label" for="email">Email</label>
                        <input class="login-input" id="email" type="email" name="email" required autocomplete="email">
                    </div>
                    <div class="login-field">
                        <label class="login-label" for="password">Password</label>
                        <input class="login-input" id="password" type="password" name="password" required minlength="8" autocomplete="new-password">
                    </div>
                    <?php if ($error): ?>
                        <div class="login-error" role="alert"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    <button type="submit" class="login-btn" id="register-submit">Create account</button>
                <?php endif; ?>
            </form>

            <p class="login-alt">Already have an account? <a href="/login.php">Sign in</a></p>
        </div>
    </div>
    <script>
    (function () {
        var form = document.getElementById('register-form');
        if (!form) return;
        form.addEventListener('submit', function () {
            var btn = document.getElementById('register-submit');
            if (btn) { btn.disabled = true; btn.textContent = 'Creating account\u2026'; }
        });
    })();
    </script>
</body>
</html>
