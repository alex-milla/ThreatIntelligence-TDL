<?php
require_once __DIR__ . '/../includes/auth.php';
sendSecurityHeaders();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
    <title><?= htmlspecialchars($pageTitle ?? 'ThreatIntelligence-TDL') ?></title>
    <link rel="stylesheet" href="/assets/css/main.css">
    <script src="/assets/whois.js"></script>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-left">
            <a href="/" class="brand">ThreatIntelligence-TDL</a>
            <?php if (!empty($_SESSION['user_id'])): ?>
                <a href="/">Dashboard</a>
                <a href="/keywords.php">Keywords</a>
                <a href="/notifications.php">Notifications</a>
                <a href="/watchlist.php">Watchlist</a>
                <?php if (!empty($_SESSION['is_admin'])): ?>
                <span class="nav-sep"></span>
                <a href="/admin/tlds.php">TLDs</a>
                <div class="nav-dropdown">
                    <button class="nav-toggle" type="button">Admin <span class="caret">&#9660;</span></button>
                    <div class="nav-dropdown-menu">
                        <a href="/admin/#overview">Overview</a>
                        <a href="/admin/#worker">Worker</a>
                        <a href="/admin/#commands">Commands</a>
                        <a href="/admin/#recheck">Recheck</a>
                        <a href="/admin/#users">Users</a>
                        <a href="/admin/#sync">Sync</a>
                        <a href="/admin/#system">System</a>
                    </div>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <div class="navbar-right">
            <?php if (!empty($_SESSION['user_id'])): ?>
                <div class="nav-dropdown">
                    <button class="nav-toggle" type="button"><?= htmlspecialchars($_SESSION['username'] ?? '') ?> <span class="caret">&#9660;</span></button>
                    <div class="nav-dropdown-menu">
                        <div class="nav-section">Account</div>
                        <a href="/account.php">Email preferences</a>
                        <?php if (!empty($_SESSION['is_admin'])): ?>
                            <a href="/admin/#users">API key</a>
                        <?php endif; ?>
                        <hr>
                        <a href="/logout.php">Cerrar sesi&oacute;n</a>
                    </div>
                </div>
            <?php else: ?>
                <a href="/login.php">Login</a>
                <a href="/register.php">Register</a>
            <?php endif; ?>
        </div>
    </nav>
    <script>
    document.querySelectorAll('.nav-dropdown').forEach(function(dd) {
        var toggle = dd.querySelector('.nav-toggle');
        toggle.addEventListener('click', function(e) {
            e.preventDefault();
            var wasOpen = dd.classList.contains('open');
            document.querySelectorAll('.nav-dropdown.open').forEach(function(o) { o.classList.remove('open'); });
            if (!wasOpen) dd.classList.add('open');
        });
    });
    document.addEventListener('click', function(e) {
        document.querySelectorAll('.nav-dropdown.open').forEach(function(dd) {
            if (!dd.contains(e.target)) dd.classList.remove('open');
        });
    });
    </script>
    <div class="container">
