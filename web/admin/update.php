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
$githubToken = ''; // Set a GitHub personal access token if repo is private
$error = '';
$info = '';

$versionFile = __DIR__ . '/../../VERSION';
$branch = 'main';

function fetchUrl(string $url, string $token = ''): array {
    $result = ['success' => false, 'data' => '', 'error' => ''];
    
    $headers = [
        'User-Agent: ThreatIntelligence-TDL-Updater',
    ];
    if ($token) {
        $headers[] = "Authorization: Bearer {$token}";
    }
    
    // Try cURL first (most reliable on shared hosting)
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
            $result['data'] = trim($data);
            return $result;
        }
        $result['error'] = "cURL error: {$curlError} (HTTP {$httpCode})";
        return $result;
    }
    
    // Fallback to file_get_contents
    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => $headers,
            'timeout' => 15,
        ],
        'ssl' => [
            'verify_peer' => true,
        ]
    ];
    $context = stream_context_create($opts);
    $data = @file_get_contents($url, false, $context);
    if ($data !== false) {
        $result['success'] = true;
        $result['data'] = trim($data);
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

// Get current installed version
if (!file_exists($versionFile)) {
    $error = 'Local VERSION file not found. Please upload the VERSION file to the hosting root.';
    $currentVersion = '0.0.0';
} else {
    $currentVersion = trim(file_get_contents($versionFile));
}

// Fetch latest version from GitHub
$remoteResult = fetchUrl("https://raw.githubusercontent.com/{$repoOwner}/{$repoName}/{$branch}/VERSION", $githubToken);
$remoteVersion = $remoteResult['success'] ? $remoteResult['data'] : null;

if ($remoteVersion === null && empty($error)) {
    $error = 'Could not fetch VERSION from GitHub. ' . $remoteResult['error'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $remoteVersion !== null && empty($error)) {
    if (version_compare($currentVersion, $remoteVersion, '>=')) {
        $info = "You are already on the latest version ({$currentVersion}). No update needed.";
    } else {
        $zipUrl = "https://github.com/{$repoOwner}/{$repoName}/archive/{$branch}.zip";
        $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
        $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();
        
        // Download ZIP
        $zipResult = fetchUrl($zipUrl, $githubToken);
        if (!$zipResult['success']) {
            $error = 'Failed to download ZIP: ' . $zipResult['error'];
        } else {
            file_put_contents($tempZip, $zipResult['data']);
            
            // Extract
            $zip = new ZipArchive();
            if ($zip->open($tempZip) === true) {
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
                    $dst = __DIR__ . '/../../' . $dir;
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
                
                // Copy VERSION file
                $srcVersion = $sourceDir . '/VERSION';
                if (file_exists($srcVersion)) {
                    copy($srcVersion, $versionFile);
                    $currentVersion = trim(file_get_contents($versionFile));
                }
                
                // Cleanup
                @unlink($tempZip);
                rrmdir($extractDir);
                
                $info = "Updated successfully to {$currentVersion}. Files copied: {$copied}.";
            } else {
                $error = 'Failed to open downloaded ZIP.';
            }
        }
    }
}
?>

<div class="card">
    <h2>System Update</h2>
    <p>This checks the latest version on GitHub <code><?= htmlspecialchars($branch) ?></code> branch and updates the application files.</p>
    <p><strong>Repository:</strong> <?= htmlspecialchars("{$repoOwner}/{$repoName}") ?></p>
    
    <table style="margin: 15px 0;">
        <tr><td><strong>Installed version:</strong></td><td><?= htmlspecialchars($currentVersion) ?></td></tr>
        <tr><td><strong>Latest version:</strong></td><td><?= htmlspecialchars($remoteVersion ?? 'Unknown') ?></td></tr>
    </table>
    
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <button type="submit" class="btn" <?= ($remoteVersion === null) ? 'disabled' : '' ?>>Check & Install Latest Version</button>
    </form>
    
    <p style="margin-top: 15px; color: #666; font-size: 0.9rem;">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) and config files will not be overwritten.
        <?php if ($remoteVersion === null): ?><br><strong>Diagnosis:</strong> Your hosting cannot reach GitHub. Check if cURL is enabled or if outgoing HTTPS is blocked.<?php endif; ?>
    </p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
