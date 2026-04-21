<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

set_time_limit(300);
ignore_user_abort(true);

$pageTitle = 'System Update';
require __DIR__ . '/../templates/header.php';

$repoOwner = 'alex-milla';
$repoName  = 'ThreatIntelligence-TDL';

// GitHub token from environment (preferred) or data file.
// For shared hosting create data/.github_token with the token.
$githubToken = getenv('GITHUB_TOKEN') ?: '';
$tokenFile   = dirname(__DIR__) . '/data/.github_token';
if (!$githubToken && file_exists($tokenFile)) {
    $githubToken = trim(file_get_contents($tokenFile));
}

$error = '';
$info  = '';

$versionFile = dirname(__DIR__) . '/VERSION';
$backupBase  = dirname(__DIR__) . '/data/backups';

function githubApiGet(string $url, string $token = ''): array {
    $result = ['success' => false, 'data' => null, 'error' => ''];
    $headers = [
        'User-Agent: ThreatIntelligence-TDL-Updater',
        'Accept: application/vnd.github+json',
    ];
    if ($token) {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        $data = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($data !== false && $httpCode >= 200 && $httpCode < 300) {
            $result['success'] = true;
            $result['data'] = json_decode($data, true);
            return $result;
        }
        if ($httpCode == 403) {
            $result['error'] = 'GitHub API rate limit exceeded. Set GITHUB_TOKEN env var or create data/.github_token.';
        } elseif ($httpCode == 404) {
            $result['error'] = 'No releases found. Create a release on GitHub first.';
        } else {
            $result['error'] = "cURL error: {$curlError} (HTTP {$httpCode})";
        }
        return $result;
    }

    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => $headers,
            'timeout' => 15,
        ]
    ];
    $context = stream_context_create($opts);
    $data = @file_get_contents($url, false, $context);
    if ($data !== false) {
        $result['success'] = true;
        $result['data'] = json_decode($data, true);
        return $result;
    }
    $result['error'] = 'file_get_contents failed. allow_url_fopen may be disabled.';
    return $result;
}

function rrmdir(string $dir): void {
    if (!is_dir($dir)) return;
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        is_dir($path) ? rrmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}

function copyDir(string $src, string $dst): int {
    $copied = 0;
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
    foreach ($rii as $file) {
        if ($file->isDir()) continue;
        $relative = substr($file->getPathname(), strlen($src) + 1);
        $target = $dst . '/' . $relative;
        @mkdir(dirname($target), 0755, true);
        copy($file->getPathname(), $target);
        $copied++;
    }
    return $copied;
}

function backupApp(string $backupBase): string {
    $timestamp = date('Ymd_His');
    $backupDir = $backupBase . '/backup_' . $timestamp;
    @mkdir($backupDir, 0755, true);

    $appRoot = dirname(__DIR__);

    // Backup all app directories except data
    $dirsToBackup = ['admin', 'api', 'assets', 'includes', 'templates', 'worker'];
    foreach ($dirsToBackup as $dir) {
        $src = $appRoot . '/' . $dir;
        if (is_dir($src)) {
            copyDir($src, $backupDir . '/' . $dir);
        }
    }

    // Backup root files
    $filesToBackup = ['index.php', 'install.php', 'keywords.php', 'login.php', 'logout.php', 'notifications.php', 'register.php', '.htaccess', 'VERSION'];
    foreach ($filesToBackup as $file) {
        $src = $appRoot . '/' . $file;
        if (file_exists($src)) {
            copy($src, $backupDir . '/' . $file);
        }
    }
    return $backupDir;
}

function doUpdate(string $zipUrl, string $versionFile, string $backupBase): array {
    $appRoot = dirname(__DIR__);

    // 1. Backup current installation
    if (!is_dir($backupBase)) {
        @mkdir($backupBase, 0755, true);
    }
    $backupDir = backupApp($backupBase);

    // 2. Download ZIP to temp
    $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
    $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();

    $zipData = @file_get_contents($zipUrl, false, stream_context_create([
        'http' => [
            'header' => ['User-Agent: ThreatIntelligence-TDL-Updater'],
            'timeout' => 120,
            'follow_location' => 1,
            'max_redirects' => 3,
        ]
    ]));
    if (!$zipData) {
        return ['success' => false, 'error' => 'Failed to download release ZIP from GitHub.', 'backup' => $backupDir];
    }

    file_put_contents($tempZip, $zipData);

    // 3. Verify ZIP integrity
    $zip = new ZipArchive();
    if ($zip->open($tempZip) !== true) {
        @unlink($tempZip);
        return ['success' => false, 'error' => 'Downloaded file is not a valid ZIP archive.', 'backup' => $backupDir];
    }
    $zip->extractTo($extractDir);
    $zip->close();

    // 4. Find extracted root (GitHub releases create a subfolder like repo-tag/)
    $entries = array_diff(scandir($extractDir), ['.', '..']);
    $sourceDir = $extractDir;
    foreach ($entries as $entry) {
        if (is_dir($extractDir . '/' . $entry)) {
            $sourceDir = $extractDir . '/' . $entry;
            break;
        }
    }

    // 5. Detect ZIP structure: legacy (has web/) or flat (modern)
    $hasLegacyWeb = is_dir($sourceDir . '/web');
    $hasWorker = is_dir($sourceDir . '/worker');
    $hasFlatApp = is_dir($sourceDir . '/admin') || is_dir($sourceDir . '/includes');

    if (!$hasLegacyWeb && !$hasFlatApp && !$hasWorker) {
        rrmdir($extractDir);
        @unlink($tempZip);
        return ['success' => false, 'error' => 'Release ZIP does not contain recognizable application files. Aborting.', 'backup' => $backupDir];
    }

    // 6. Copy files
    $copied = 0;

    if ($hasLegacyWeb) {
        // Legacy mode: copy web/ → root, worker/ → worker/
        foreach (['web', 'worker'] as $dir) {
            $src = $sourceDir . '/' . $dir;
            $dst = $appRoot . '/' . $dir;
            if (!is_dir($src)) continue;

            $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
            foreach ($rii as $file) {
                if ($file->isDir()) continue;
                $relative = substr($file->getPathname(), strlen($src) + 1);

                if (strpos($relative, 'data/') === 0 || strpos($relative, 'data\\') === 0) {
                    continue;
                }

                $target = $dst . '/' . $relative;
                @mkdir(dirname($target), 0755, true);
                copy($file->getPathname(), $target);
                $copied++;
            }
        }
    } else {
        // Flat mode: copy everything from ZIP root except exclusions
        $excluded = ['data', '.git', 'README.md', '.gitignore'];
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceDir));
        foreach ($rii as $file) {
            if ($file->isDir()) continue;
            $relative = substr($file->getPathname(), strlen($sourceDir) + 1);
            $parts = explode('/', str_replace('\\', '/', $relative));
            $topDir = $parts[0] ?? '';
            $fileName = basename($relative);

            if (in_array($topDir, $excluded, true) || in_array($fileName, $excluded, true)) {
                continue;
            }
            if (strpos($relative, 'data/') === 0 || strpos($relative, 'data\\') === 0) {
                continue;
            }

            $target = $appRoot . '/' . $relative;
            @mkdir(dirname($target), 0755, true);
            copy($file->getPathname(), $target);
            $copied++;
        }
    }

    // 7. Cleanup
    @unlink($tempZip);
    rrmdir($extractDir);

    return ['success' => true, 'copied' => $copied, 'backup' => $backupDir];
}

// Get current installed version
$currentVersion = '0.0.0';
if (file_exists($versionFile)) {
    $currentVersion = trim(file_get_contents($versionFile));
}

// Fetch latest release from GitHub
$apiResult = githubApiGet("https://api.github.com/repos/{$repoOwner}/{$repoName}/releases/latest", $githubToken);
$release = $apiResult['success'] ? $apiResult['data'] : null;
$remoteVersion = '';
$zipUrl = '';
$releaseNotes = '';
$publishedAt = '';

if ($release) {
    $remoteVersion = ltrim($release['tag_name'] ?? '', 'v');
    $zipUrl = $release['zipball_url'] ?? '';
    $releaseNotes = $release['body'] ?? '';
    $publishedAt = $release['published_at'] ?? '';
}

if (!$release && empty($error)) {
    $error = $apiResult['error'];
}

$forceUpdate = isset($_POST['force']) && $_POST['force'] === '1';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $release && empty($error)) {
    validateCsrf();

    if (!$forceUpdate && version_compare($currentVersion, $remoteVersion, '>=')) {
        $info = "You are already on the latest release (v{$currentVersion}). No update needed.";
    } elseif (empty($zipUrl)) {
        $error = 'No download URL found in the release.';
    } else {
        $result = doUpdate($zipUrl, $versionFile, $backupBase);
        if ($result['success']) {
            file_put_contents($versionFile, $remoteVersion);
            $action = $forceUpdate ? 'Force updated' : 'Updated';
            $info = "{$action} successfully to v{$remoteVersion}. Files copied: {$result['copied']}.<br>Backup saved to: <code>" . htmlspecialchars(basename($result['backup'])) . "</code>";
        } else {
            $error = $result['error'];
            if (!empty($result['backup'])) {
                $error .= '<br>Backup available at: <code>' . htmlspecialchars(basename($result['backup'])) . '</code>';
            }
        }
    }
}

// List available backups
$backups = [];
if (is_dir($backupBase)) {
    foreach (glob($backupBase . '/backup_*') as $b) {
        $backups[] = basename($b);
    }
    rsort($backups);
}
?>

<div class="card">
    <h2>System Update</h2>
    <p>This checks the latest <strong>GitHub Release</strong> and updates the application files.</p>
    <p><strong>Repository:</strong> <?= htmlspecialchars("{$repoOwner}/{$repoName}") ?></p>

    <table style="margin: 15px 0;">
        <tr><td><strong>Installed version:</strong></td><td>v<?= htmlspecialchars($currentVersion) ?></td></tr>
        <tr><td><strong>Latest release:</strong></td><td><?= $remoteVersion ? 'v' . htmlspecialchars($remoteVersion) : '<em>Unknown</em>' ?></td></tr>
        <?php if ($publishedAt): ?>
        <tr><td><strong>Published:</strong></td><td><?= htmlspecialchars($publishedAt) ?></td></tr>
        <?php endif; ?>
    </table>

    <?php if ($releaseNotes): ?>
    <details style="margin-bottom: 15px;">
        <summary>Release Notes</summary>
        <pre style="background: #f8f9fa; padding: 12px; border-radius: 4px; white-space: pre-wrap;"><?= htmlspecialchars($releaseNotes) ?></pre>
    </details>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert alert-error"><?= $error ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><?= $info ?></div>
    <?php endif; ?>

    <?php if (!$githubToken && $release === null): ?>
    <div class="alert alert-error" style="margin-bottom: 15px;">
        <strong>Private repository detected or rate limited.</strong><br>
        Create a file <code>data/.github_token</code> with a GitHub Personal Access Token to access releases.
    </div>
    <?php endif; ?>

    <form method="POST" style="margin-bottom: 10px;">
        <?php csrfField(); ?>
        <button type="submit" class="btn">Check & Install Latest Release</button>
    </form>

    <form method="POST">
        <?php csrfField(); ?>
        <input type="hidden" name="force" value="1">
        <button type="submit" class="btn btn-danger">Force Reinstall Latest Release</button>
    </form>

    <p style="margin-top: 15px; color: #666; font-size: 0.9rem;">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) and config files will not be overwritten.<br>
        A full backup of application files and <code>worker/</code> is created automatically before every update.<br>
        <?php if ($release === null): ?><strong>Diagnosis:</strong> No GitHub release found. Create one at <code>https://github.com/alex-milla/ThreatIntelligence-TDL/releases</code> or check your token if the repo is private.<?php endif; ?>
    </p>
</div>

<?php if (!empty($backups)): ?>
<div class="card">
    <h2>Backups</h2>
    <p>Stored in <code>data/backups/</code></p>
    <table>
        <thead>
            <tr><th>Backup</th><th>Size</th></tr>
        </thead>
        <tbody>
            <?php foreach (array_slice($backups, 0, 10) as $b):
                $bPath = $backupBase . '/' . $b;
                $size = is_dir($bPath) ? 'Dir' : 'File';
            ?>
            <tr>
                <td><?= htmlspecialchars($b) ?></td>
                <td><?= htmlspecialchars($size) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../templates/footer.php'; ?>
