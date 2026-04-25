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

<style>
#tld-search { width: 100%; padding: 10px 14px; font-size: 1rem; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 15px; box-sizing: border-box; }
#tld-search:focus { outline: none; border-color: #3498db; }
.tld-table-container { max-height: 70vh; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 4px; }
.tld-row.hidden { display: none; }
#tld-count { font-size: 0.9rem; color: #666; margin-bottom: 10px; }
.tld-table-container table { margin: 0; }
.tld-table-container thead th { position: sticky; top: 0; background: #f8f9fa; z-index: 1; }
</style>

<div class="card">
    <h2>Approved TLDs (<?= count($tlds) ?>)</h2>
    <p>Check the TLDs you want the worker to monitor. Unchecked TLDs will be ignored.</p>
    
    <?php if (empty($tlds)): ?>
    <div class="alert alert-error">
        No TLDs found. The worker must run at least once to populate this list from ICANN CZDS.
        <br>Go to <a href="/admin/"><strong>Admin Panel</strong></a> and click <strong>Run Worker Now</strong>.
    </div>
    <?php else: ?>
    <input type="text" id="tld-search" placeholder="Search TLDs..." onkeyup="filterTlds()">
    <form method="POST">
        <?php csrfField(); ?>
        <div style="margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
            <button type="button" class="btn btn-small" onclick="selectAllTlds(true)">Select All</button>
            <button type="button" class="btn btn-small" onclick="selectAllTlds(false)">Deselect All</button>
            <button type="submit" class="btn">Save Selection</button>
            <span id="tld-count"></span>
        </div>
        
        <div class="tld-table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px;">Active</th>
                        <th>TLD</th>
                        <th>Last Sync</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="tld-tbody">
                    <?php foreach ($tlds as $t): ?>
                    <tr class="tld-row" data-name="<?= htmlspecialchars($t['name']) ?>">
                        <td style="text-align: center;">
                            <input type="checkbox" name="active[]" value="<?= htmlspecialchars($t['name']) ?>" <?= $t['is_active'] ? 'checked' : '' ?> onchange="updateTldCount()">
                        </td>
                        <td><?= htmlspecialchars($t['name']) ?></td>
                        <td><?= htmlspecialchars($t['last_sync'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($t['status'] ?? '-') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <div style="margin-top: 15px;">
            <button type="submit" class="btn">Save Selection</button>
        </div>
    </form>
    <?php endif; ?>
</div>

<script>
function filterTlds() {
    const query = document.getElementById('tld-search').value.toLowerCase().trim();
    document.querySelectorAll('.tld-row').forEach(row => {
        const name = row.dataset.name.toLowerCase();
        row.classList.toggle('hidden', query && !name.includes(query));
    });
    updateTldCount();
}

function selectAllTlds(checked) {
    document.querySelectorAll('.tld-row:not(.hidden) input[name="active[]"]').forEach(cb => cb.checked = checked);
    updateTldCount();
}

function updateTldCount() {
    const visible = document.querySelectorAll('.tld-row:not(.hidden)').length;
    const checked = document.querySelectorAll('.tld-row:not(.hidden) input[name="active[]"]:checked').length;
    document.getElementById('tld-count').textContent = checked + ' of ' + visible + ' visible TLDs selected';
}

updateTldCount();
</script>

<?php require __DIR__ . '/../templates/footer.php'; ?>
