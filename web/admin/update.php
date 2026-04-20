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

$versionFile = __DIR__ . '/../../.version';
$branch = 'main';

function githubApiGet(string $url, string $token = ''): ?array {
    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => [
                'User-Agent: ThreatIntelligence-TDL-Updater',
                'Accept: application/vnd.github+json',
            ],
            'timeout' => 15,
        ]
    ];
    if ($token) {
        $opts['http']['header'][] = "Authorization: Bearer {$token}";
    }
    $context = stream_context_create($opts);
    $response = @file_get_contents($url, false, $context);
    if ($response === false) return null;
    return json_decode($response, true);
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
$currentSha = file_exists($versionFile) ? trim(file_get_contents($versionFile)) : 'none';

// Fetch latest commit from GitHub
$commitData = githubApiGet("https://api.github.com/repos/{$repoOwner}/{$repoName}/commits/{$branch}", $githubToken);
$latestSha = $commitData['sha'] ?? '';
$latestMessage = $commitData['commit']['message'] ?? 'Unknown';

if (!$latestSha) {
    $error = 'Could not fetch latest commit from GitHub. Rate limit exceeded or repository is inaccessible.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $latestSha) {
    if ($currentSha === $latestSha) {
        $info = 'You are already on the latest version (' . substr($latestSha, 0, 7) . '). No update needed.';
    } else {
        $zipUrl = "https://github.com/{$repoOwner}/{$repoName}/archive/{$branch}.zip";
        $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
        $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();
        
        // Download ZIP
        $zipData = @file_get_contents($zipUrl, false, stream_context_create([
            'http' => ['header' => ['User-Agent: ThreatIntelligence-TDL-Updater'], 'timeout' => 120]
        ]));
        if (!$zipData) {
            $error = 'Failed to download source ZIP from GitHub.';
        } else {
            file_put_contents($tempZip, $zipData);
            
            // Extract
            $zip = new ZipArchive();
            if ($zip->open($tempZip) === true) {
                $zip->extractTo($extractDir);
                $zip->close();
                
                // Find extracted root (GitHub adds owner-repo-branch-hash folder)
                $entries = array_diff(scandir($extractDir), ['.', '..']);
                $sourceDir = $extractDir;
                foreach ($entries as $entry) {
                    if (is_dir($extractDir . '/' . $entry)) {
                        $sourceDir = $extractDir . '/' . $entry;
                        break;
                    }
                }
                
                // Copy web/ and worker/ directories
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
                
                // Save new version
                file_put_contents($versionFile, $latestSha);
                
                // Cleanup
                @unlink($tempZip);
                rrmdir($extractDir);
                
                $info = "Updated successfully from {$currentSha} to " . substr($latestSha, 0, 7) . ". Files copied: {$copied}. Commit: " . substr($latestMessage, 0, 60) . "...";
            } else {
                $error = 'Failed to open downloaded ZIP.';
            }
        }
    }
}
?>

<div class="card">
    <h2>System Update</h2>
    <p>This checks the latest commit on GitHub <code><?= htmlspecialchars($branch) ?></code> branch and updates the application files.</p>
    <p><strong>Repository:</strong> <?= htmlspecialchars("{$repoOwner}/{$repoName}") ?></p>
    
    <table style="margin: 15px 0;">
        <tr><td><strong>Installed version:</strong></td><td><code><?= htmlspecialchars(substr($currentSha, 0, 7)) ?></code></td></tr>
        <tr><td><strong>Latest version:</strong></td><td><code><?= htmlspecialchars(substr($latestSha, 0, 7)) ?></code></td></tr>
        <tr><td><strong>Latest commit:</strong></td><td><?= htmlspecialchars($latestMessage) ?></td></tr>
    </table>
    
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <button type="submit" class="btn">Check & Install Latest Commit</button>
    </form>
    
    <p style="margin-top: 15px; color: #666; font-size: 0.9rem;">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) and config files will not be overwritten. 
        If the repository is private, edit this file and set <code>$githubToken</code>.
    </p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
