<?php
require_once __DIR__ . '/../includes/auth.php';
sendSecurityHeaders();

$loggedIn = !empty($_SESSION['user_id']);
$isAdmin = !empty($_SESSION['is_admin']);
$username = $_SESSION['username'] ?? '';

$assetVersion = '0';
if (is_file(__DIR__ . '/../VERSION')) {
    $assetVersion = trim((string)file_get_contents(__DIR__ . '/../VERSION'));
}

// Current page (for active nav state)
$curPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$current = basename($curPath);
if ($curPath === '' || $curPath === '/') {
    $current = 'index.php';
}
$isAdminArea = strpos($curPath, '/admin') === 0;

// Sidebar active states
$isDashboard     = ($current === 'index.php' && !$isAdminArea);
$isKeywords      = in_array($current, ['keywords.php', 'keyword_matches.php'], true);
$isNotifications = ($current === 'notifications.php');
$isWatchlist     = ($current === 'watchlist.php');
$isReports       = in_array($current, ['reports.php', 'report_view.php'], true);
$isTlds          = ($current === 'tlds.php');
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
    <meta name="theme-color" content="#f97316">
    <title><?= htmlspecialchars($pageTitle ?? 'ThreatIntelligence-TDL') ?></title>
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
<div class="app-shell">

    <?php if ($loggedIn): ?>
    <aside class="app-sidebar" id="app-sidebar">
        <a href="/" class="sidebar-brand">
            <span class="sidebar-logo"><i class="material-icons">security</i></span>
            <span>ThreatIntel</span>
        </a>
        <nav class="sidebar-nav">
            <div class="sidebar-group-label">Monitoring</div>
            <a href="/" class="sidebar-link<?= $isDashboard ? ' active' : '' ?>">
                <i class="material-icons">dashboard</i>Dashboard
            </a>
            <a href="/keywords.php" class="sidebar-link<?= $isKeywords ? ' active' : '' ?>">
                <i class="material-icons">search</i>Keywords
            </a>
            <a href="/notifications.php" class="sidebar-link<?= $isNotifications ? ' active' : '' ?>">
                <i class="material-icons">notifications</i>Notifications
            </a>
            <a href="/watchlist.php" class="sidebar-link<?= $isWatchlist ? ' active' : '' ?>">
                <i class="material-icons">visibility</i>Watchlist
            </a>

            <div class="sidebar-group-label">Intelligence</div>
            <a href="/reports.php" class="sidebar-link<?= $isReports ? ' active' : '' ?>">
                <i class="material-icons">assessment</i>Informes
            </a>

            <?php if ($isAdmin): ?>
            <div class="sidebar-group-label">Administration</div>
            <a href="/admin/tlds.php" class="sidebar-link<?= $isTlds ? ' active' : '' ?>">
                <i class="material-icons">public</i>TLDs
            </a>
            <a href="/admin/" class="sidebar-link<?= $isAdminArea ? ' active' : '' ?>">
                <i class="material-icons">admin_panel_settings</i>Admin Panel
            </a>
            <?php endif; ?>
        </nav>
    </aside>
    <?php endif; ?>

    <div class="app-body">
        <header class="app-header">
            <div style="display:flex; align-items:center; gap:12px; min-width:0;">
                <?php if ($loggedIn): ?>
                <a href="#" data-target="mobile-nav" class="sidenav-trigger" aria-label="Open navigation menu">
                    <i class="material-icons">menu</i>
                </a>
                <?php endif; ?>
                <span class="app-header-brand<?= $loggedIn ? ' mobile-only' : '' ?>">ThreatIntelligence-TDL</span>
                <h1 class="app-header-title"><?= htmlspecialchars($pageTitle ?? 'ThreatIntelligence-TDL') ?></h1>
            </div>

            <div class="app-header-actions">
                <a href="#!" data-theme-toggle class="icon-btn theme-toggle" role="button" aria-label="Switch to dark mode">
                    <i class="material-icons">dark_mode</i>
                </a>
                <?php if ($loggedIn): ?>
                    <a class="dropdown-trigger user-menu" href="#!" data-target="account-dropdown" aria-haspopup="true">
                        <i class="material-icons">person</i>
                        <span class="hide-on-small-only"><?= htmlspecialchars($username) ?></span>
                        <?php if ($isAdmin): ?><span class="role-chip hide-on-small-only">Admin</span><?php endif; ?>
                        <i class="material-icons">arrow_drop_down</i>
                    </a>
                <?php else: ?>
                    <a href="/login.php" class="btn btn-small waves-effect">Login</a>
                    <a href="/register.php" class="btn btn-small btn-outline waves-effect hide-on-small-only">Register</a>
                <?php endif; ?>
            </div>
        </header>

        <?php if ($loggedIn): ?>
        <ul class="sidenav" id="mobile-nav">
            <li><div class="user-view"><span class="name"><?= htmlspecialchars($username) ?></span><?php if ($isAdmin): ?> <span class="role-chip">Admin</span><?php endif; ?></div></li>
            <li><a href="/" class="<?= $isDashboard ? 'active' : '' ?>"><i class="material-icons">dashboard</i>Dashboard</a></li>
            <li><a href="/keywords.php" class="<?= $isKeywords ? 'active' : '' ?>"><i class="material-icons">search</i>Keywords</a></li>
            <li><a href="/notifications.php" class="<?= $isNotifications ? 'active' : '' ?>"><i class="material-icons">notifications</i>Notifications</a></li>
            <li><a href="/watchlist.php" class="<?= $isWatchlist ? 'active' : '' ?>"><i class="material-icons">visibility</i>Watchlist</a></li>
            <li><a href="/reports.php" class="<?= $isReports ? 'active' : '' ?>"><i class="material-icons">assessment</i>Informes</a></li>
            <?php if ($isAdmin): ?>
                <li><div class="sidenav-group-label">Administration</div></li>
                <li><a href="/admin/tlds.php" class="<?= $isTlds ? 'active' : '' ?>"><i class="material-icons">public</i>TLDs</a></li>
                <li><a href="/admin/" class="<?= $isAdminArea ? 'active' : '' ?>"><i class="material-icons">admin_panel_settings</i>Admin Panel</a></li>
            <?php endif; ?>
            <li><div class="divider"></div></li>
            <li><a href="/account.php" class="<?= $current === 'account.php' ? 'active' : '' ?>"><i class="material-icons">mail</i>Account</a></li>
            <li><a href="/logout.php"><i class="material-icons">logout</i>Logout</a></li>
        </ul>
        <?php else: ?>
        <ul class="sidenav" id="mobile-nav">
            <li><a href="/login.php" class="<?= $current === 'login.php' ? 'active' : '' ?>"><i class="material-icons">login</i>Login</a></li>
            <li><a href="/register.php" class="<?= $current === 'register.php' ? 'active' : '' ?>"><i class="material-icons">person_add</i>Register</a></li>
        </ul>
        <?php endif; ?>

        <?php if ($loggedIn): ?>
        <ul id="account-dropdown" class="dropdown-content">
            <li><a href="/account.php"><i class="material-icons">mail</i>Email preferences</a></li>
            <?php if ($isAdmin): ?>
                <li><a href="/admin/"><i class="material-icons">vpn_key</i>API key</a></li>
            <?php endif; ?>
            <li class="divider" tabindex="-1"></li>
            <li><a href="/logout.php"><i class="material-icons">logout</i>Logout</a></li>
        </ul>
        <?php endif; ?>

        <main>
            <div class="container">
