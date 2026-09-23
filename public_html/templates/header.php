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
$isAdminPanel    = ($isAdminArea && !$isTlds);
$tldSource       = (string)($_GET['source'] ?? 'czds');
if (!in_array($tldSource, ['czds', 'openintel'], true)) {
    $tldSource = 'czds';
}
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

            <?php if ($isAdmin): ?>
            <div class="sidebar-subgroup<?= $isTlds ? ' is-open' : '' ?>">
                <button type="button" class="sidebar-link sidebar-parent<?= $isTlds ? ' active' : '' ?>" data-submenu-toggle="sidebar-tlds" aria-expanded="<?= $isTlds ? 'true' : 'false' ?>">
                    <i class="material-icons">public</i>TLDs
                    <i class="material-icons sidebar-caret">expand_more</i>
                </button>
                <div class="sidebar-submenu" id="sidebar-tlds">
                    <a href="/admin/tlds.php?source=czds" class="sidebar-sublink<?= ($isTlds && $tldSource === 'czds') ? ' active' : '' ?>">ICANN (CZDS)</a>
                    <a href="/admin/tlds.php?source=openintel" class="sidebar-sublink<?= ($isTlds && $tldSource === 'openintel') ? ' active' : '' ?>">ccTLD (OpenINTEL)</a>
                </div>
            </div>
            <?php endif; ?>

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
            <div class="sidebar-subgroup<?= $isAdminPanel ? ' is-open' : '' ?>">
                <button type="button" class="sidebar-link sidebar-parent<?= $isAdminPanel ? ' active' : '' ?>" data-submenu-toggle="sidebar-admin" aria-expanded="<?= $isAdminPanel ? 'true' : 'false' ?>">
                    <i class="material-icons">admin_panel_settings</i>Admin Panel
                    <i class="material-icons sidebar-caret">expand_more</i>
                </button>
                <div class="sidebar-submenu" id="sidebar-admin">
                    <a href="/admin/#overview" class="sidebar-sublink" data-admin-tab="overview">Overview</a>
                    <a href="/admin/#worker" class="sidebar-sublink" data-admin-tab="worker">Worker</a>
                    <a href="/admin/#commands" class="sidebar-sublink" data-admin-tab="commands">Commands</a>
                    <a href="/admin/#recheck" class="sidebar-sublink" data-admin-tab="recheck">Recheck</a>
                    <a href="/admin/#users" class="sidebar-sublink" data-admin-tab="users">Users</a>
                    <a href="/admin/#sync" class="sidebar-sublink" data-admin-tab="sync">Sync</a>
                    <a href="/admin/#system" class="sidebar-sublink" data-admin-tab="system">System</a>
                </div>
            </div>
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
            <?php if ($isAdmin): ?>
            <li class="sidenav-subgroup<?= $isTlds ? ' is-open' : '' ?>">
                <div class="sidenav-parent<?= $isTlds ? ' active' : '' ?>" data-submenu-toggle="m-tlds" role="button" tabindex="0" aria-expanded="<?= $isTlds ? 'true' : 'false' ?>" aria-controls="m-tlds">
                    <i class="material-icons">public</i>TLDs
                    <i class="material-icons sidenav-caret">expand_more</i>
                </div>
                <ul class="sidenav-submenu" id="m-tlds">
                    <li><a href="/admin/tlds.php?source=czds" class="<?= ($isTlds && $tldSource === 'czds') ? 'active' : '' ?>">ICANN (CZDS)</a></li>
                    <li><a href="/admin/tlds.php?source=openintel" class="<?= ($isTlds && $tldSource === 'openintel') ? 'active' : '' ?>">ccTLD (OpenINTEL)</a></li>
                </ul>
            </li>
            <?php endif; ?>
            <li><a href="/keywords.php" class="<?= $isKeywords ? 'active' : '' ?>"><i class="material-icons">search</i>Keywords</a></li>
            <li><a href="/notifications.php" class="<?= $isNotifications ? 'active' : '' ?>"><i class="material-icons">notifications</i>Notifications</a></li>
            <li><a href="/watchlist.php" class="<?= $isWatchlist ? 'active' : '' ?>"><i class="material-icons">visibility</i>Watchlist</a></li>
            <li><a href="/reports.php" class="<?= $isReports ? 'active' : '' ?>"><i class="material-icons">assessment</i>Informes</a></li>
            <?php if ($isAdmin): ?>
                <li><div class="sidenav-group-label">Administration</div></li>
                <li class="sidenav-subgroup<?= $isAdminPanel ? ' is-open' : '' ?>">
                    <div class="sidenav-parent<?= $isAdminPanel ? ' active' : '' ?>" data-submenu-toggle="m-admin" role="button" tabindex="0" aria-expanded="<?= $isAdminPanel ? 'true' : 'false' ?>" aria-controls="m-admin">
                        <i class="material-icons">admin_panel_settings</i>Admin Panel
                        <i class="material-icons sidenav-caret">expand_more</i>
                    </div>
                    <ul class="sidenav-submenu" id="m-admin">
                        <li><a href="/admin/#overview" data-admin-tab="overview">Overview</a></li>
                        <li><a href="/admin/#worker" data-admin-tab="worker">Worker</a></li>
                        <li><a href="/admin/#commands" data-admin-tab="commands">Commands</a></li>
                        <li><a href="/admin/#recheck" data-admin-tab="recheck">Recheck</a></li>
                        <li><a href="/admin/#users" data-admin-tab="users">Users</a></li>
                        <li><a href="/admin/#sync" data-admin-tab="sync">Sync</a></li>
                        <li><a href="/admin/#system" data-admin-tab="system">System</a></li>
                    </ul>
                </li>
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
