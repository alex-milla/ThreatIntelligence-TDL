<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

$lockFile = __DIR__ . '/data/.installed';

if (file_exists($lockFile)) {
    header('Location: /');
    exit;
}

// Hard gate: if an admin already exists in the database, redirect even without lock file
$db = Database::get();
$hasAdmin = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_admin=1")->fetchColumn();
if ($hasAdmin > 0) {
    header('Location: /');
    exit;
}

$step = $_GET['step'] ?? 'check';
$error = '';
$success = '';

if ($step === 'check') {
    $dataDir = __DIR__ . '/data';
    $writable = is_dir($dataDir) && is_writable($dataDir);
    if (!$writable) {
        @mkdir($dataDir, 0755, true);
        $writable = is_writable($dataDir);
    }
    
    $db = Database::get();
    $tablesExist = true;
    try {
        $db->query("SELECT 1 FROM users LIMIT 1");
    } catch (PDOException $e) {
        $tablesExist = false;
    }
    
    if ($writable && !$tablesExist) {
        header('Location: install.php?step=create');
        exit;
    }
}

if ($step === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email = trim($_POST['email'] ?? '');
    
    if (strlen($username) < 3 || strlen($password) < 8 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid input. Username min 3 chars, password min 8 chars, valid email required.";
    } else {
        $db = Database::get();
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $apiKey = bin2hex(random_bytes(32));
        
        $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, api_key, is_admin, max_keywords) VALUES (?, ?, ?, ?, 1, 0)");
        try {
            $stmt->execute([$username, $email, $hash, $apiKey]);
            touch($lockFile);
            $success = "Admin user created successfully.";
            $showKey = $apiKey;
        } catch (PDOException $e) {
            $error = "Database error: " . $e->getMessage();
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
    <meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
    <title>Install - ThreatIntelligence-TDL</title>
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
    <link rel="stylesheet" href="/css/materialize.min.css?v=<?= urlencode($assetVersion) ?>">
    <link rel="stylesheet" href="/css/materialize.colors.min.css?v=<?= urlencode($assetVersion) ?>">
    <link rel="stylesheet" href="/css/app.css?v=<?= urlencode($assetVersion) ?>">
</head>
<body>
    <main>
        <div class="container">
            <div class="card auth-card">
                <div class="auth-logo">
                    <i class="material-icons">security</i>
                    <h2>Installation</h2>
                </div>
                <p class="muted">Create the first administrator account to finish setting up ThreatIntelligence-TDL.</p>

                <?php if ($error): ?>
                    <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($success) ?></div>
                    <p><strong>API Key for Worker:</strong></p>
                    <div class="api-key"><?= htmlspecialchars($showKey) ?></div>
                    <p>Copy this key into your worker <code>config.ini</code> under <code>api_key</code>.</p>
                    <p><a href="/" class="btn waves-effect"><i class="material-icons left">dashboard</i>Go to Dashboard</a></p>
                <?php else: ?>
                    <form method="POST" action="install.php?step=create">
                        <?php csrfField(); ?>
                        <div class="input-field">
                            <i class="material-icons prefix">person</i>
                            <input id="username" type="text" name="username" placeholder=" " required minlength="3">
                            <label for="username">Admin Username</label>
                        </div>
                        <div class="input-field">
                            <i class="material-icons prefix">email</i>
                            <input id="email" type="email" name="email" placeholder=" " required>
                            <label for="email">Admin Email</label>
                        </div>
                        <div class="input-field">
                            <i class="material-icons prefix">lock</i>
                            <input id="password" type="password" name="password" placeholder=" " required minlength="8">
                            <label for="password">Admin Password</label>
                        </div>
                        <button type="submit" class="btn waves-effect" style="width:100%;"><i class="material-icons left">build</i>Create Admin &amp; Install</button>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </main>
    <script src="/js/materialize.min.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/js/app.js?v=<?= urlencode($assetVersion) ?>"></script>
</body>
</html>
