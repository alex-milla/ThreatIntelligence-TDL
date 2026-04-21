<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

set_time_limit(300);
ignore_user_abort(true);

$pageTitle = 'System Update';
require __DIR__ . '/../templates/header.php';

$repoOwner = 'alex-milla';
$repoName = 'ThreatIntelligence-TDL';
$githubToken = ''; // <-- Set a GitHub personal access token here if repo is private or to avoid rate limits
$error = '';
$info = '';

$versionFile = dirname(__DIR__) . '/VERSION';

function githubApiGet(string $url, string $token = ''): array {
    $result = ['success' => false, 'data' => null, 'error' => ''];
    $headers = [
        'User-Agent: ThreatIntelligence-TDL-Updater',
        'Accept: application/vnd.github+json',
    ];
    if ($token) {
        $headers[] = "Authorization: Bearer {$token}";
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
            $result['error'] = 'GitHub API rate limit exceeded. Set a personal access token in update.php.';
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

function doUpdate(string $zipUrl, string $versionFile): array {
    $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
    $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();

    // Download ZIP
    $zipData = @file_get_contents($zipUrl, false, stream_context_create([
        'http' => ['header' => ['User-Agent: ThreatIntelligence-TDL-Updater'], 'timeout' => 120]
    ]));
    if (!$zipData) {
        return ['success' => false, 'error' => 'Failed to download release ZIP from GitHub.'];
    }

    file_put_contents($tempZip, $zipData);

    $zip = new ZipArchive();
    if ($zip->open($tempZip) !== true) {
        return ['success' => false, 'error' => 'Failed to open downloaded ZIP.'];
    }

    $zip->extractTo($extractDir);
    $zip->close();

    // Find extracted root
    $entries = array_diff(scandir($extractDir), ['.', '..']);
    $sourceDir = $extractDir;
    foreach ($entries as $entry) {
        if (is_dir($extractDir . '/' . $entry)) {
            $sourceDir = $extractDir . '/' . $entry;
            break;
        }
    }

    // Copy web/ and worker/
    $copied = 0;
    foreach (['web', 'worker'] as $dir) {
        $src = $sourceDir . '/' . $dir;
        $dst = dirname(__DIR__) . '/' . $dir;
        if (is_dir($src)) {
            $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
            foreach ($rii as $file) {
                if ($file->isDir()) continue;
                $relative = substr($file->getPathname(), strlen($src) + 1);
                $target = $dst . '/' . $relative;
                @mkdir(dirname($target), 0755, true);
                copy($file->getPathname(), $target);
                $copied++;
            }
        }
    }

    // Cleanup
    @unlink($tempZip);
    rrmdir($extractDir);

    return ['success' => true, 'copied' => $copied];
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
    if (!$forceUpdate && version_compare($currentVersion, $remoteVersion, '>=')) {
        $info = "You are already on the latest release (v{$currentVersion}). No update needed.";
    } elseif (empty($zipUrl)) {
        $error = 'No download URL found in the release.';
    } else {
        $result = doUpdate($zipUrl, $versionFile);
        if ($result['success']) {
            // Write new version
            file_put_contents($versionFile, $remoteVersion);
            $action = $forceUpdate ? 'Force updated' : 'Updated';
            $info = "{$action} successfully to v{$remoteVersion}. Files copied: {$result['copied']}.";
        } else {
            $error = $result['error'];
        }
    }
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
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
    <?php endif; ?>

    <form method="POST" style="margin-bottom: 10px;">
        <button type="submit" class="btn" <?= ($release === null) ? 'disabled' : '' ?>>Check & Install Latest Release</button>
    </form>

    <form method="POST">
        <input type="hidden" name="force" value="1">
        <button type="submit" class="btn btn-danger" <?= ($release === null) ? 'disabled' : '' ?>>Force Reinstall Latest Release</button>
    </form>

    <p style="margin-top: 15px; color: #666; font-size: 0.9rem;">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) and config files will not be overwritten.
        <?php if ($release === null): ?><br><strong>Diagnosis:</strong> No GitHub release found. Create one at <code>https://github.com/alex-milla/ThreatIntelligence-TDL/releases</code><?php endif; ?>
    </p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
