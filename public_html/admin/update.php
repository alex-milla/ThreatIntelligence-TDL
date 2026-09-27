<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/updater.php';
requireAdmin();

set_time_limit(300);
ignore_user_abort(true);

// Flash message survives the post-update redirect (new code reloads the page).
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

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

function doUpdate(string $zipUrl, string $versionFile, string $backupBase): array {
    $appRoot = dirname(__DIR__);

    // 1. Backup current installation (helpers live in includes/updater.php).
    if (!is_dir($backupBase)) {
        @mkdir($backupBase, 0755, true);
    }
    $backupDir = tdl_backup_app($backupBase);
    tdl_prune_backups($backupBase, 10);

    // 2. Download ZIP to temp (prefer cURL for proper redirect handling)
    $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
    $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();

    $downloadError = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($zipUrl);
        $fp = fopen($tempZip, 'wb');
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 120);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'ThreatIntelligence-TDL-Updater');
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if ($httpCode < 200 || $httpCode >= 300) {
            $downloadError = "GitHub download failed: HTTP {$httpCode}. {$curlError}";
            @unlink($tempZip);
        }
    } else {
        $zipData = @file_get_contents($zipUrl, false, stream_context_create([
            'http' => [
                'header' => ['User-Agent: ThreatIntelligence-TDL-Updater'],
                'timeout' => 120,
                'follow_location' => 1,
                'max_redirects' => 3,
            ]
        ]));
        if ($zipData) {
            file_put_contents($tempZip, $zipData);
        } else {
            $downloadError = 'Failed to download release ZIP from GitHub (file_get_contents). allow_url_fopen may be disabled.';
        }
    }

    if ($downloadError || !file_exists($tempZip) || filesize($tempZip) < 1024) {
        @unlink($tempZip);
        return ['success' => false, 'error' => $downloadError ?: 'Downloaded ZIP is empty or corrupt.', 'backup' => $backupDir];
    }

    // 3. Verify ZIP integrity and reject path-traversal entries before extracting.
    $zip = new ZipArchive();
    if ($zip->open($tempZip) !== true) {
        @unlink($tempZip);
        return ['success' => false, 'error' => 'Downloaded file is not a valid ZIP archive.', 'backup' => $backupDir];
    }
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $entry = (string)$zip->getNameIndex($i);
        if (tdl_zip_entry_unsafe($entry)) {
            $zip->close();
            @unlink($tempZip);
            return [
                'success' => false,
                'error'   => 'Release ZIP contains an unsafe path and was rejected: <code>' . htmlspecialchars($entry) . '</code>',
                'backup'  => $backupDir,
            ];
        }
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

    // 5. Detect ZIP structure:
    //    - public_html/ (v1.3.55+): web root is public_html/, worker/ at repo root
    //    - web/  : legacy layout
    //    - flat  : admin/ and includes/ at ZIP root (pre-public_html)
    $hasPublicHtml = is_dir($sourceDir . '/public_html');
    $hasLegacyWeb  = is_dir($sourceDir . '/web');
    $hasWorker     = is_dir($sourceDir . '/worker');
    $hasFlatApp    = is_dir($sourceDir . '/admin') || is_dir($sourceDir . '/includes');

    if (!$hasPublicHtml && !$hasLegacyWeb && !$hasFlatApp && !$hasWorker) {
        tdl_rrmdir($extractDir);
        @unlink($tempZip);
        return ['success' => false, 'error' => 'Release ZIP does not contain recognizable application files. Aborting.', 'backup' => $backupDir];
    }

    // 6. Copy only new/changed files (manifest), then prune files that the new
    //    release no longer ships. The modern layout tracks a SHA-256 manifest;
    //    legacy/flat layouts keep the previous full-copy behaviour.
    $repoRoot   = dirname($appRoot);
    $dataDir    = $appRoot . '/data';
    $prevManifest = tdl_load_manifest($dataDir);
    $newManifest  = [];
    $changed   = 0;
    $unchanged = 0;
    $removed   = 0;

    if ($hasPublicHtml) {
        // Modern layout: copy public_html/* into the web root and worker/* next to it.
        $r = tdl_sync_tree(
            $sourceDir . '/public_html',
            $appRoot,
            ['data', '.git', '.github'],
            [],
            'public_html/',
            $newManifest
        );
        $changed += $r['changed'];
        $unchanged += $r['unchanged'];

        if ($hasWorker) {
            $r = tdl_sync_tree(
                $sourceDir . '/worker',
                $repoRoot . '/worker',
                ['data', 'logs', 'zones', '__pycache__'],
                ['config.ini'],
                'worker/',
                $newManifest
            );
            $changed += $r['changed'];
            $unchanged += $r['unchanged'];
        }

        $removed = tdl_prune_removed($prevManifest, $newManifest, $appRoot, $repoRoot);
        tdl_save_manifest($dataDir, $newManifest);
    } elseif ($hasLegacyWeb) {
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
                $changed++;
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
            $changed++;
        }
    }

    // 7. Cleanup
    @unlink($tempZip);
    tdl_rrmdir($extractDir);

    return [
        'success'   => true,
        'copied'    => $changed,
        'unchanged' => $unchanged,
        'removed'   => $removed,
        'backup'    => $backupDir,
    ];
}

// Get current installed version
$currentVersion = '0.0.0';
if (file_exists($versionFile)) {
    $currentVersion = trim(file_get_contents($versionFile));
}

// Fetch latest release from GitHub (try releases first, then tags)
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

// Fallback: if no release found, try tags API (works when only git tags exist)
if (!$release && (empty($error) || strpos($apiResult['error'] ?? '', '404') !== false)) {
    $tagsResult = githubApiGet("https://api.github.com/repos/{$repoOwner}/{$repoName}/tags?per_page=1", $githubToken);
    if ($tagsResult['success'] && !empty($tagsResult['data'][0])) {
        $tag = $tagsResult['data'][0];
        $tagName = $tag['name'] ?? '';
        $remoteVersion = ltrim($tagName, 'v');
        $zipUrl = "https://github.com/{$repoOwner}/{$repoName}/archive/refs/tags/{$tagName}.zip";
        $publishedAt = $tag['published_at'] ?? '';
        // For tags we don't have release notes, but we can still update
        $release = ['tag_name' => $tagName]; // mark as found so buttons work
    }
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
            // Redirect (PRG) so the browser reloads the freshly installed files
            // and the message is shown by the new version.
            $_SESSION['flash_message'] = "{$action} successfully to v{$remoteVersion}. Files copied: {$result['copied']}"
                . (isset($result['unchanged']) ? ", unchanged: {$result['unchanged']}" : '')
                . (isset($result['removed']) && $result['removed'] > 0 ? ", removed: {$result['removed']}" : '')
                . ".<br>Backup saved to: <code>" . htmlspecialchars(basename($result['backup'])) . "</code>";
            header('Location: /admin/update.php');
            exit;
        } else {
            $error = $result['error'];
            if (!empty($result['backup'])) {
                $error .= '<br>Backup available at: <code>' . htmlspecialchars(basename($result['backup'])) . '</code>';
            }
        }
    }
}

$pageTitle = 'System Update';
require __DIR__ . '/../templates/header.php';
?>

<div class="card">
    <div class="page-header">
        <h1>System Update</h1>
        <p class="subtitle">Check the latest GitHub Release and update the application files. Repository: <strong><?= htmlspecialchars("{$repoOwner}/{$repoName}") ?></strong></p>
    </div>
    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= $message ?></div>
    <?php endif; ?>

    <table class="striped">
        <tbody>
        <tr><td><strong>Installed version:</strong></td><td>v<?= htmlspecialchars($currentVersion) ?></td></tr>
        <tr><td><strong>Latest release:</strong></td><td><?= $remoteVersion ? 'v' . htmlspecialchars($remoteVersion) : '<em>Unknown</em>' ?></td></tr>
        <?php if ($publishedAt): ?>
        <tr><td><strong>Published:</strong></td><td><?= htmlspecialchars($publishedAt) ?></td></tr>
        <?php endif; ?>
        </tbody>
    </table>

    <?php if ($releaseNotes): ?>
    <details class="release-notes">
        <summary>Release Notes</summary>
        <pre><?= htmlspecialchars($releaseNotes) ?></pre>
    </details>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= $error ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= $info ?></div>
    <?php endif; ?>

    <?php if (!$githubToken && $release === null): ?>
    <div class="alert alert-error">
        <i class="material-icons left">vpn_key</i>
        <strong>Private repository detected or rate limited.</strong><br>
        Create a file <code>data/.github_token</code> with a GitHub Personal Access Token to access releases.
    </div>
    <?php endif; ?>

    <div class="section-actions">
        <form method="POST">
            <?php csrfField(); ?>
            <button type="submit" class="btn waves-effect"><i class="material-icons left">system_update</i>Check &amp; Install Latest Release</button>
        </form>

        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="force" value="1">
            <button type="submit" class="btn btn-danger waves-effect"><i class="material-icons left">restart_alt</i>Force Reinstall Latest Release</button>
        </form>

        <a href="/admin/backups.php" class="btn btn-outline waves-effect"><i class="material-icons left">inventory_2</i>Backups</a>
    </div>

    <p class="muted">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) and config files will not be overwritten.<br>
        A snapshot of the application files is created automatically before every update; manage and restore them from <a href="/admin/backups.php">Backups</a>.<br>
        <?php if ($release === null): ?><strong>Diagnosis:</strong> No GitHub release found. Create one at <code>https://github.com/alex-milla/ThreatIntelligence-TDL/releases</code> or check your token if the repo is private.<?php endif; ?>
    </p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
