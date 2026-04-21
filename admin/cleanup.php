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
    <h2>Cleanup False-Positive Matches</h2>
    <p>This tool removes matches where the keyword only appeared in the TLD (e.g. <code>abcd1234.life</code> matching keyword <code>life</code>).</p>
    
    <?php if ($message): ?>
    <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    
    <?php if ($falseCount > 0): ?>
        <div class="alert alert-error">
            <strong><?= $falseCount ?></strong> false-positive match(es) found.
        </div>
        
        <h3>Examples (first 10):</h3>
        <table>
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
        
        <form method="POST" style="margin-top: 15px;">
            <?php csrfField(); ?>
            <button type="submit" class="btn btn-danger" onclick="return confirm('Delete <?= $falseCount ?> false match(es)? This cannot be undone.')">Delete False Matches</button>
        </form>
    <?php else: ?>
        <p>No false-positive matches found. Everything looks clean!</p>
    <?php endif; ?>
    
    <p style="margin-top: 15px;"><a href="/admin/" class="btn">Back to Admin Panel</a></p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
