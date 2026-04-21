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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Install - ThreatIntelligence-TDL</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #f5f5f5; }
        .box { background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; }
        label { display: block; margin-top: 15px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { margin-top: 20px; padding: 12px 24px; background: #007bff; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: #dc3545; margin-top: 15px; }
        .success { color: #28a745; margin-top: 15px; }
        .api-key { background: #e9ecef; padding: 15px; border-radius: 4px; font-family: monospace; word-break: break-all; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="box">
        <h1>ThreatIntelligence-TDL Installation</h1>
        
        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?= htmlspecialchars($success) ?></div>
            <p><strong>API Key for Worker:</strong></p>
            <div class="api-key"><?= htmlspecialchars($showKey) ?></div>
            <p>Copy this key into your worker <code>config.ini</code> under <code>api_key</code>.</p>
            <p><a href="/">Go to Dashboard</a></p>
        <?php else: ?>
            <form method="POST" action="install.php?step=create">
                <?php csrfField(); ?>
                <label>Admin Username</label>
                <input type="text" name="username" required minlength="3">
                
                <label>Admin Email</label>
                <input type="email" name="email" required>
                
                <label>Admin Password</label>
                <input type="password" name="password" required minlength="8">
                
                <button type="submit">Create Admin & Install</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
