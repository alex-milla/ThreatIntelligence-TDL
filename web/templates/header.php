<?php
require_once __DIR__ . '/../includes/auth.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle ?? 'ThreatIntelligence-TDL') ?></title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; background: #f5f7fa; color: #333; }
        .navbar { background: #1a1a2e; color: #fff; padding: 0 20px; display: flex; align-items: center; justify-content: space-between; }
        .navbar a { color: #fff; text-decoration: none; padding: 15px 12px; display: inline-block; }
        .navbar a:hover { background: #16213e; }
        .navbar .brand { font-weight: bold; font-size: 1.1rem; }
        .container { max-width: 1100px; margin: 30px auto; padding: 0 20px; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 20px; }
        .card h2 { margin-top: 0; font-size: 1.25rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .btn { display: inline-block; padding: 8px 16px; background: #007bff; color: #fff; text-decoration: none; border-radius: 4px; border: none; cursor: pointer; font-size: 0.95rem; }
        .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #a71d2a; }
        .btn-small { padding: 4px 10px; font-size: 0.85rem; }
        .form-group { margin-bottom: 15px; }
        label { display: block; font-weight: 600; margin-bottom: 5px; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        .alert { padding: 12px 16px; border-radius: 4px; margin-bottom: 15px; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .alert-success { background: #d4edda; color: #155724; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: #fff; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        .stat-box .number { font-size: 2rem; font-weight: bold; color: #007bff; }
        .stat-box .label { color: #666; margin-top: 5px; }
        .unread { background: #fff3cd; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div>
            <a href="/" class="brand">ThreatIntelligence-TDL</a>
            <?php if (!empty($_SESSION['user_id'])): ?>
                <a href="/">Dashboard</a>
                <a href="/keywords.php">Keywords</a>
                <a href="/notifications.php">Notifications</a>
            <?php endif; ?>
        </div>
        <div>
            <?php if (!empty($_SESSION['user_id'])): ?>
                <span style="padding: 15px 12px; display: inline-block;"><?= htmlspecialchars($_SESSION['username'] ?? '') ?></span>
                <a href="/logout.php">Logout</a>
            <?php else: ?>
                <a href="/login.php">Login</a>
                <a href="/register.php">Register</a>
            <?php endif; ?>
        </div>
    </nav>
    <div class="container">
