<?php
/**
 * Backups: list the application snapshots taken before every update/restore and
 * restore one of them. Restoring copies the backed-up app (and worker source when
 * present on this host) files back, never touching data/ or config.ini. Only the
 * 10 most recent backups are kept.
 */
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/updater.php';
requireAdmin();

set_time_limit(300);

$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);
$error = '';

$backupBase = dirname(__DIR__) . '/data/backups';
$maxBackups = 10;

// Restore a backup (admin + CSRF). A snapshot of the current state is taken
// first, so the restore itself is reversible.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'restore') {
    validateCsrf();
    $name = basename((string)($_POST['backup'] ?? ''));
    $dir  = $backupBase . '/' . $name;
    if ($name === '' || strpos($name, 'backup_') !== 0 || !is_dir($dir)) {
        $error = 'Invalid backup selected.';
    } else {
        $safety = tdl_backup_app($backupBase);
        tdl_prune_backups($backupBase, $maxBackups);
        $res = tdl_restore_backup($dir, dirname(__DIR__), dirname(dirname(__DIR__)), dirname(__DIR__) . '/data');
        if (!empty($res['success'])) {
            $_SESSION['flash_message'] = "Restored <code>" . htmlspecialchars($name) . "</code>. Files restored: {$res['changed']}, removed: {$res['removed']}. "
                . "Pre-restore snapshot: <code>" . htmlspecialchars(basename($safety)) . "</code>.";
            header('Location: /admin/backups.php');
            exit;
        }
        $error = $res['error'] ?? 'Restore failed.';
    }
}

// Enforce the retention cap and list the available backups (newest first).
tdl_prune_backups($backupBase, $maxBackups);
$backups = [];
foreach (glob($backupBase . '/backup_*') ?: [] as $b) {
    if (is_dir($b)) {
        $backups[] = basename($b);
    }
}
rsort($backups);

function backupBytes(int $bytes): string {
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 1) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 1) . ' KB';
    return $bytes . ' B';
}

function backupDate(string $name): string {
    if (preg_match('/^backup_(\d{8})_(\d{6})$/', $name, $m)) {
        $ts = strtotime($m[1] . ' ' . $m[2]);
        if ($ts) {
            return date('Y-m-d H:i:s', $ts);
        }
    }
    return $name;
}

$pageTitle = 'Backups';
require __DIR__ . '/../templates/header.php';
?>

<div class="card">
    <div class="page-header">
        <h1>Backups</h1>
        <span class="count-chip"><i class="material-icons" style="font-size:16px;">inventory_2</i><?= count($backups) ?> / <?= (int)$maxBackups ?></span>
        <span class="spacer"></span>
        <a href="/admin/update.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">system_update</i>System Update</a>
        <p class="subtitle">Snapshots taken automatically before every update or restore. Only the <?= (int)$maxBackups ?> most recent are kept. Stored in <code>data/backups/</code>.</p>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= $message ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= $error ?></div>
    <?php endif; ?>

    <div class="hint-bar">
        <span class="hint"><i class="material-icons">restore</i>Restoring overwrites the <strong>web application files</strong> of this host (and <code>worker/</code> only if it lives next to <code>public_html</code>). <code>data/</code> and <code>config.ini</code> are never touched, and a pre-restore snapshot is taken first.</span>
        <span class="hint"><i class="material-icons">dns</i>The worker runs on its own host and is reverted with git, not from here.</span>
    </div>

    <?php if (empty($backups)): ?>
        <p class="muted">No backups yet. One is created automatically before every update or restore.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th>Backup</th>
                    <th>Created</th>
                    <th>Contents</th>
                    <th>Size</th>
                    <th style="width: 120px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($backups as $b):
                    $bPath = $backupBase . '/' . $b;
                    $hasWorker = is_dir($bPath . '/worker');
                    $size = tdl_dir_size($bPath);
                ?>
                <tr>
                    <td><code><?= htmlspecialchars($b) ?></code></td>
                    <td><?= htmlspecialchars(backupDate($b)) ?></td>
                    <td><?= is_dir($bPath . '/public_html') ? 'App' : '' ?><?= (is_dir($bPath . '/public_html') && $hasWorker) ? ' + ' : '' ?><?= $hasWorker ? 'Worker' : '' ?></td>
                    <td><?= htmlspecialchars(backupBytes($size['bytes'])) ?><?= $size['truncated'] ? '…' : '' ?></td>
                    <td>
                        <div class="row-actions">
                            <form method="POST" onsubmit="return confirm('Restore <?= htmlspecialchars($b, ENT_QUOTES) ?>? The current files will be snapshotted first.');">
                                <?php csrfField(); ?>
                                <input type="hidden" name="action" value="restore">
                                <input type="hidden" name="backup" value="<?= htmlspecialchars($b) ?>">
                                <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">restore</i>Restore</button>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
