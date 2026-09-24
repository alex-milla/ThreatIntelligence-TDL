<?php
/**
 * Intelligence: dormant-domain tracking.
 *
 * Lists the (domain, keyword) pairs the worker follows for the keyword's
 * tracking window and shows whether they stayed dormant or showed an
 * activation signal.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/tracking.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);

$validStatuses = ['all', 'tracking', 'activated', 'dormant'];
$status = (string)($_GET['status'] ?? 'all');
if (!in_array($status, $validStatuses, true)) {
    $status = 'all';
}
$search = trim((string)($_GET['q'] ?? ''));

$where = "WHERE dt.user_id = ?";
$params = [$userId];
if ($status !== 'all') {
    $where .= " AND dt.status = ?";
    $params[] = $status;
}
if ($search !== '') {
    $where .= " AND (dt.domain LIKE ? OR k.keyword LIKE ?)";
    $like = '%' . $search . '%';
    $params[] = $like;
    $params[] = $like;
}

$sql = "SELECT dt.id, dt.domain, dt.keyword_id, dt.first_seen, dt.enrolled_at, dt.expires_at,
        dt.status, dt.check_count, dt.last_checked_at, dt.next_check_at, dt.activated_at,
        dt.activated_reason, k.keyword, dw.creation_date
    FROM domain_tracking dt
    JOIN keywords k ON k.id = dt.keyword_id
    LEFT JOIN domain_whois dw ON dw.domain = dt.domain
    $where
    ORDER BY CASE dt.status WHEN 'activated' THEN 0 WHEN 'tracking' THEN 1 ELSE 2 END,
             dt.next_check_at ASC, dt.domain ASC";
$stmt = $db->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

// Status counts for the summary.
$cntStmt = $db->prepare("SELECT status, COUNT(*) AS n FROM domain_tracking WHERE user_id = ? GROUP BY status");
$cntStmt->execute([$userId]);
$counts = ['tracking' => 0, 'activated' => 0, 'dormant' => 0];
foreach ($cntStmt->fetchAll() as $c) {
    $counts[$c['status']] = (int)$c['n'];
}

$statusMeta = [
    'tracking'  => ['Running', 'status-running'],
    'activated' => ['Activated', 'status-pending'],
    'dormant'   => ['Dormant', 'status-cancelled'],
];

$pageTitle = 'Intelligence';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2>Intelligence &mdash; dormant domain tracking</h2>
        <span class="muted"><?= count($rows) ?> shown</span>
    </div>

    <p class="muted">
        Recently registered keyword matches that are still clean are followed for a while.
        If they show an activation signal (reputation, WHOIS/NS changes) you get a notification.
        Configure the window and cadence per keyword in <a href="/keywords.php">Keywords</a>.
    </p>

    <div class="section-actions">
        <a class="btn btn-small waves-effect <?= $status === 'all' ? '' : 'btn-outline' ?>" href="/intelligence.php?status=all<?= $search !== '' ? '&q=' . urlencode($search) : '' ?>">All</a>
        <a class="btn btn-small waves-effect <?= $status === 'tracking' ? '' : 'btn-outline' ?>" href="/intelligence.php?status=tracking<?= $search !== '' ? '&q=' . urlencode($search) : '' ?>">Tracking (<?= $counts['tracking'] ?>)</a>
        <a class="btn btn-small waves-effect <?= $status === 'activated' ? '' : 'btn-outline' ?>" href="/intelligence.php?status=activated<?= $search !== '' ? '&q=' . urlencode($search) : '' ?>">Activated (<?= $counts['activated'] ?>)</a>
        <a class="btn btn-small waves-effect <?= $status === 'dormant' ? '' : 'btn-outline' ?>" href="/intelligence.php?status=dormant<?= $search !== '' ? '&q=' . urlencode($search) : '' ?>">Dormant (<?= $counts['dormant'] ?>)</a>
        <form method="GET" action="/intelligence.php" style="display:inline-flex; gap:6px; margin-left:8px;">
            <input type="hidden" name="status" value="<?= htmlspecialchars($status) ?>">
            <input type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder="Domain or keyword" class="browser-default compact">
            <button type="submit" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">search</i>Filter</button>
        </form>
        <?php if ($isAdmin): ?>
        <button type="button" class="btn btn-small waves-effect" onclick="intelCheckAll()"><i class="material-icons left">refresh</i>Check all due</button>
        <?php endif; ?>
    </div>

    <?php if (empty($rows)): ?>
        <p class="muted">Nothing here yet. Tracked domains appear when a keyword has tracking enabled and a recent clean match is found.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Keyword</th>
                    <th>Age</th>
                    <th>Enrolled</th>
                    <th>Ends</th>
                    <th>Status</th>
                    <th>Checks</th>
                    <th>Last check</th>
                    <th>Signal</th>
                    <th style="width: 170px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($rows as $r):
                    $meta = $statusMeta[$r['status']] ?? ['Unknown', 'status-cancelled'];
                    $ageDays = trackingAgeDays($r['creation_date']);
                    $expTs = $r['expires_at'] ? strtotime((string)$r['expires_at'] . ' UTC') : null;
                    $daysLeft = $expTs ? (int)ceil(($expTs - time()) / 86400) : null;
                    $domainArg = htmlspecialchars(addslashes((string)$r['domain']), ENT_QUOTES);
                ?>
                <tr>
                    <td><strong><?= htmlspecialchars($r['domain']) ?></strong></td>
                    <td><a href="/keyword_matches.php?id=<?= (int)$r['keyword_id'] ?>"><?= htmlspecialchars($r['keyword']) ?></a></td>
                    <td><?= $ageDays !== null ? ($ageDays . ' d') : '—' ?></td>
                    <td><?= $r['enrolled_at'] ? htmlspecialchars(substr(fmt_date((string)$r['enrolled_at']), 0, 10)) : '—' ?></td>
                    <td><?= $daysLeft !== null ? ($daysLeft >= 0 ? ($daysLeft . ' d') : 'expired') : '—' ?></td>
                    <td><span class="status-badge <?= htmlspecialchars($meta[1]) ?>"><?= htmlspecialchars($meta[0]) ?></span></td>
                    <td><?= (int)$r['check_count'] ?></td>
                    <td><?= $r['last_checked_at'] ? htmlspecialchars(fmt_date((string)$r['last_checked_at'])) : '—' ?></td>
                    <td><?= $r['activated_reason'] !== '' && $r['activated_reason'] !== null ? '<span class="muted">' . htmlspecialchars((string)$r['activated_reason']) . '</span>' : '<span class="muted">&mdash;</span>' ?></td>
                    <td>
                        <div class="action-menu">
                            <button type="button" class="action-menu-btn" aria-label="Row actions" aria-haspopup="true" onclick="toggleMenu(this)"><i class="material-icons">more_vert</i></button>
                            <div class="action-menu-dropdown">
                                <?php if ($isAdmin): ?>
                                <a href="javascript:void(0)" onclick="intelCheck(<?= (int)$r['id'] ?>, '<?= $domainArg ?>')"><i class="material-icons">refresh</i>Check now</a>
                                <?php endif; ?>
                                <a href="javascript:void(0)" onclick="intelExtend(<?= (int)$r['id'] ?>)"><i class="material-icons">schedule</i>Extend</a>
                                <a href="javascript:void(0)" onclick="intelClear(<?= (int)$r['id'] ?>)"><i class="material-icons">visibility_off</i>Mark dormant</a>
                                <a href="javascript:void(0)" onclick="intelDelete(<?= (int)$r['id'] ?>)" class="red-text"><i class="material-icons">delete</i>Delete</a>
                            </div>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
