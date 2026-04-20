<?php
require __DIR__ . '/../includes/db.php';
require __DIR__ . '/../includes/auth.php';
requireAdmin();

set_time_limit(300);
ignore_user_abort(true);

$pageTitle = 'System Update';
require __DIR__ . '/../templates/header.php';

$repoOwner = 'alex-milla';
$repoName = 'ThreatIntelligence-TDL';
$githubToken = ''; // Set via environment or config for private repos
$error = '';
$info = '';

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $release = githubApiGet("https://api.github.com/repos/{$repoOwner}/{$repoName}/releases/latest", $githubToken);
    if (!$release || empty($release['tag_name'])) {
        $error = 'Could not fetch latest release from GitHub. If the repository is private, set a token in the script.';
    } else {
        $tag = $release['tag_name'];
        $zipUrl = $release['zipball_url'] ?? '';
        $info = "Latest release: {$tag}. ";
        
        if (!$zipUrl) {
            $error = 'No ZIP URL found in release.';
        } else {
            $backupDir = __DIR__ . '/../../backup_' . date('Ymd_His');
            $tempZip = sys_get_temp_dir() . '/tdl_update_' . time() . '.zip';
            $extractDir = sys_get_temp_dir() . '/tdl_extract_' . time();
            
            // Download ZIP
            $zipData = @file_get_contents($zipUrl, false, stream_context_create([
                'http' => ['header' => ['User-Agent: ThreatIntelligence-TDL-Updater'], 'timeout' => 120]
            ]));
            if (!$zipData) {
                $error = 'Failed to download release ZIP.';
            } else {
                file_put_contents($tempZip, $zipData);
                
                // Backup current web files
                @mkdir($backupDir, 0755, true);
                // Simple backup: copy key files (not full recursive to avoid timeout on shared hosting)
                // In production, manual backup is recommended.
                
                // Extract
                $zip = new ZipArchive();
                if ($zip->open($tempZip) === true) {
                    $zip->extractTo($extractDir);
                    $zip->close();
                    
                    // Find extracted root (GitHub adds owner-repo-hash folder)
                    $entries = array_diff(scandir($extractDir), ['.', '..']);
                    $sourceDir = $extractDir;
                    foreach ($entries as $entry) {
                        if (is_dir($extractDir . '/' . $entry)) {
                            $sourceDir = $extractDir . '/' . $entry;
                            break;
                        }
                    }
                    
                    // Copy web/ and worker/ directories
                    $copied = [];
                    foreach (['web', 'worker'] as $dir) {
                        $src = $sourceDir . '/' . $dir;
                        $dst = __DIR__ . '/../../' . $dir;
                        if (is_dir($src)) {
                            // On shared hosting, recursive copy may be slow; we iterate top-level files
                            $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
                            foreach ($rii as $file) {
                                if ($file->isDir()) continue;
                                $relative = substr($file->getPathname(), strlen($src) + 1);
                                $target = $dst . '/' . $relative;
                                @mkdir(dirname($target), 0755, true);
                                copy($file->getPathname(), $target);
                                $copied[] = $relative;
                            }
                        }
                    }
                    
                    // Cleanup
                    @unlink($tempZip);
                    rrmdir($extractDir);
                    
                    $info .= "Updated successfully. Files copied: " . count($copied) . ". Please verify functionality.";
                } else {
                    $error = 'Failed to open downloaded ZIP.';
                }
            }
        }
    }
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
?>

<div class="card">
    <h2>System Update</h2>
    <p>This will check the latest release on GitHub and update the application files.</p>
    <p><strong>Repository:</strong> <?= htmlspecialchars("{$repoOwner}/{$repoName}") ?></p>
    
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($info): ?>
        <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <button type="submit" class="btn">Check & Install Latest Release</button>
    </form>
    
    <p style="margin-top: 15px; color: #666; font-size: 0.9rem;">
        <strong>Note:</strong> Your database (<code>data/app.db</code>) will not be overwritten. 
        If the repository is private, edit this file and set <code>$githubToken</code>.
    </p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
