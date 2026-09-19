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
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
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
    <header>
        <nav class="app-nav">
            <div class="nav-wrapper container">
                <a href="/" class="brand-logo">ThreatIntelligence-TDL</a>
                <a href="#" data-target="mobile-nav" class="sidenav-trigger" aria-label="Open navigation menu"><i class="material-icons">menu</i></a>
                <ul class="right hide-on-med-and-down">
                    <?php if ($loggedIn): ?>
                        <li><a href="/" class="<?= ($current === 'index.php' && !$isAdminArea) ? 'active' : '' ?>" aria-current="<?= ($current === 'index.php' && !$isAdminArea) ? 'page' : 'false' ?>"><i class="material-icons left">dashboard</i>Dashboard</a></li>
                        <li><a href="/keywords.php" class="<?= $current === 'keywords.php' ? 'active' : '' ?>" aria-current="<?= $current === 'keywords.php' ? 'page' : 'false' ?>"><i class="material-icons left">search</i>Keywords</a></li>
                        <li><a href="/notifications.php" class="<?= $current === 'notifications.php' ? 'active' : '' ?>" aria-current="<?= $current === 'notifications.php' ? 'page' : 'false' ?>"><i class="material-icons left">notifications</i>Notifications</a></li>
                        <li><a href="/watchlist.php" class="<?= $current === 'watchlist.php' ? 'active' : '' ?>" aria-current="<?= $current === 'watchlist.php' ? 'page' : 'false' ?>"><i class="material-icons left">visibility</i>Watchlist</a></li>
                        <?php if ($isAdmin): ?>
                            <li><a href="/admin/tlds.php" class="<?= $current === 'tlds.php' ? 'active' : '' ?>" aria-current="<?= $current === 'tlds.php' ? 'page' : 'false' ?>"><i class="material-icons left">public</i>TLDs</a></li>
                            <li>
                                <a class="dropdown-trigger<?= $isAdminArea ? ' active' : '' ?>" href="#!" data-target="admin-dropdown" aria-haspopup="true" aria-current="<?= $isAdminArea ? 'page' : 'false' ?>">
                                    <i class="material-icons left">admin_panel_settings</i>Admin
                                    <i class="material-icons right">arrow_drop_down</i>
                                </a>
                            </li>
                        <?php endif; ?>
                    <?php endif; ?>
                    <li>
                        <a href="#!" data-theme-toggle class="theme-toggle" role="button" aria-label="Switch to dark mode">
                            <i class="material-icons">dark_mode</i>
                        </a>
                    </li>
                    <?php if ($loggedIn): ?>
                        <li>
                            <a class="dropdown-trigger" href="#!" data-target="account-dropdown" aria-haspopup="true">
                                <i class="material-icons left">account_circle</i><?= htmlspecialchars($username) ?>
                                <i class="material-icons right">arrow_drop_down</i>
                            </a>
                        </li>
                    <?php else: ?>
                        <li><a href="/login.php" class="<?= $current === 'login.php' ? 'active' : '' ?>"><i class="material-icons left">login</i>Login</a></li>
                        <li><a href="/register.php" class="<?= $current === 'register.php' ? 'active' : '' ?>"><i class="material-icons left">person_add</i>Register</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </nav>
    </header>

    <?php if ($loggedIn): ?>
    <ul class="sidenav" id="mobile-nav">
        <li><div class="user-view"><span class="name"><?= htmlspecialchars($username) ?></span></div></li>
        <li><a href="/" class="<?= ($current === 'index.php' && !$isAdminArea) ? 'active' : '' ?>"><i class="material-icons">dashboard</i>Dashboard</a></li>
        <li><a href="/keywords.php" class="<?= $current === 'keywords.php' ? 'active' : '' ?>"><i class="material-icons">search</i>Keywords</a></li>
        <li><a href="/notifications.php" class="<?= $current === 'notifications.php' ? 'active' : '' ?>"><i class="material-icons">notifications</i>Notifications</a></li>
        <li><a href="/watchlist.php" class="<?= $current === 'watchlist.php' ? 'active' : '' ?>"><i class="material-icons">visibility</i>Watchlist</a></li>
        <?php if ($isAdmin): ?>
            <li><div class="divider"></div></li>
            <li><a href="/admin/tlds.php" class="<?= $current === 'tlds.php' ? 'active' : '' ?>"><i class="material-icons">public</i>TLDs</a></li>
            <li><a href="/admin/#overview" class="<?= $isAdminArea ? 'active' : '' ?>"><i class="material-icons">admin_panel_settings</i>Admin Panel</a></li>
        <?php endif; ?>
        <li><div class="divider"></div></li>
        <li><a href="#!" data-theme-toggle><i class="material-icons">dark_mode</i>Theme</a></li>
        <li><a href="/account.php" class="<?= $current === 'account.php' ? 'active' : '' ?>"><i class="material-icons">mail</i>Account</a></li>
        <li><a href="/logout.php"><i class="material-icons">logout</i>Logout</a></li>
    </ul>
    <?php else: ?>
    <ul class="sidenav" id="mobile-nav">
        <li><a href="/login.php" class="<?= $current === 'login.php' ? 'active' : '' ?>"><i class="material-icons">login</i>Login</a></li>
        <li><a href="/register.php" class="<?= $current === 'register.php' ? 'active' : '' ?>"><i class="material-icons">person_add</i>Register</a></li>
        <li><div class="divider"></div></li>
        <li><a href="#!" data-theme-toggle><i class="material-icons">dark_mode</i>Theme</a></li>
    </ul>
    <?php endif; ?>

    <?php if ($isAdmin): ?>
    <ul id="admin-dropdown" class="dropdown-content">
        <li><a href="/admin/#overview"><i class="material-icons">dashboard</i>Overview</a></li>
        <li><a href="/admin/#worker"><i class="material-icons">memory</i>Worker</a></li>
        <li><a href="/admin/#commands"><i class="material-icons">playlist_play</i>Commands</a></li>
        <li><a href="/admin/#recheck"><i class="material-icons">restart_alt</i>Recheck</a></li>
        <li><a href="/admin/tlds.php"><i class="material-icons">public</i>TLDs</a></li>
        <li class="divider" tabindex="-1"></li>
        <li><a href="/admin/#users"><i class="material-icons">people</i>Users</a></li>
        <li><a href="/admin/#sync"><i class="material-icons">sync</i>Sync</a></li>
        <li><a href="/admin/#system"><i class="material-icons">settings</i>System</a></li>
    </ul>
    <?php endif; ?>

    <?php if ($loggedIn): ?>
    <ul id="account-dropdown" class="dropdown-content">
        <li><a href="/account.php"><i class="material-icons">mail</i>Email preferences</a></li>
        <?php if ($isAdmin): ?>
            <li><a href="/admin/#users"><i class="material-icons">vpn_key</i>API key</a></li>
        <?php endif; ?>
        <li class="divider" tabindex="-1"></li>
        <li><a href="/logout.php"><i class="material-icons">logout</i>Logout</a></li>
    </ul>
    <?php endif; ?>

    <main>
        <div class="container">
