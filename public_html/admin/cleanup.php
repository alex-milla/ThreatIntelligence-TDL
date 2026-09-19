<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = '';

// Find false-positive matches (keyword only appears in TLD, not in domain name)
$stmt = $db->query("SELECT m.id, m.domain, k.keyword 
    FROM matches m 
    JOIN keywords k ON m.keyword_id = k.id");
$falseIds = [];
$falseExamples = [];

foreach ($stmt->fetchAll() as $row) {
    $domainLower = strtolower($row['domain']);
    $keywordLower = strtolower($row['keyword']);
    $namePart = $domainLower;
    if (strpos($domainLower, '.') !== false) {
        $namePart = substr($domainLower, 0, strrpos($domainLower, '.'));
    }
    if (strpos($namePart, $keywordLower) === false) {
        $falseIds[] = (int)$row['id'];
        if (count($falseExamples) < 10) {
            $falseExamples[] = $row;
        }
    }
}

$falseCount = count($falseIds);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $falseCount > 0) {
    validateCsrf();
    $placeholders = implode(',', array_fill(0, $falseCount, '?'));
    
    // Delete associated notifications first
    $db->prepare("DELETE FROM notifications WHERE match_id IN ($placeholders)")->execute($falseIds);
    
    // Delete false matches
    $db->prepare("DELETE FROM matches WHERE id IN ($placeholders)")->execute($falseIds);
    
    $message = "$falseCount false-positive match(es) deleted successfully.";
    $falseCount = 0;
    $falseExamples = [];
}

$pageTitle = 'Cleanup False Matches';
require __DIR__ . '/../templates/header.php';
?>

<div class="card">
    <div class="card-head"><h2>Cleanup False-Positive Matches</h2></div>
    <p>This tool removes matches where the keyword only appeared in the TLD (e.g. <code>abcd1234.life</code> matching keyword <code>life</code>).</p>

    <?php if ($message): ?>
    <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if ($falseCount > 0): ?>
        <div class="alert alert-error">
            <i class="material-icons left">warning</i>
            <strong><?= $falseCount ?></strong> false-positive match(es) found.
        </div>

        <h5>Examples (first 10):</h5>
        <table class="striped highlight responsive-table">
            <thead>
                <tr><th>Domain</th><th>Keyword</th></tr>
            </thead>
            <tbody>
                <?php foreach ($falseExamples as $ex): ?>
                <tr>
                    <td><?= htmlspecialchars($ex['domain']) ?></td>
                    <td><?= htmlspecialchars($ex['keyword']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <form method="POST" class="section-actions">
            <?php csrfField(); ?>
            <button type="submit" class="btn btn-danger waves-effect" onclick="return confirm('Delete <?= $falseCount ?> false match(es)? This cannot be undone.')"><i class="material-icons left">delete_sweep</i>Delete False Matches</button>
        </form>
    <?php else: ?>
        <p class="text-success"><i class="material-icons left">check_circle</i>No false-positive matches found. Everything looks clean!</p>
    <?php endif; ?>

    <p><a href="/admin/" class="btn waves-effect"><i class="material-icons left">arrow_back</i>Back to Admin Panel</a></p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
