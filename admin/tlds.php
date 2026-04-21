<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $active = $_POST['active'] ?? [];
    $db->beginTransaction();
    $db->exec("UPDATE tlds SET is_active = 0");
    $stmt = $db->prepare("UPDATE tlds SET is_active = 1 WHERE name = ?");
    foreach ($active as $tld) {
        $stmt->execute([$tld]);
    }
    $db->commit();
    $message = 'TLD selection saved. The worker will use these on next run.';
}

$tlds = $db->query("SELECT id, name, is_active, last_sync, status FROM tlds ORDER BY name")->fetchAll();

$pageTitle = 'Manage TLDs';
require __DIR__ . '/../templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Approved TLDs (<?= count($tlds) ?>)</h2>
    <p>Check the TLDs you want the worker to monitor. Unchecked TLDs will be ignored.</p>
    
    <form method="POST">
        <?php csrfField(); ?>
        <div style="margin-bottom: 15px;">
            <button type="button" class="btn btn-small" onclick="document.querySelectorAll('input[name=active[]]').forEach(c => c.checked = true)">Select All</button>
            <button type="button" class="btn btn-small" onclick="document.querySelectorAll('input[name=active[]]').forEach(c => c.checked = false)">Deselect All</button>
            <button type="submit" class="btn">Save Selection</button>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th style="width: 40px;">Active</th>
                    <th>TLD</th>
                    <th>Last Sync</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tlds as $t): ?>
                <tr>
                    <td style="text-align: center;">
                        <input type="checkbox" name="active[]" value="<?= htmlspecialchars($t['name']) ?>" <?= $t['is_active'] ? 'checked' : '' ?>>
                    </td>
                    <td><?= htmlspecialchars($t['name']) ?></td>
                    <td><?= htmlspecialchars($t['last_sync'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($t['status'] ?? '-') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        
        <div style="margin-top: 15px;">
            <button type="submit" class="btn">Save Selection</button>
        </div>
    </form>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
