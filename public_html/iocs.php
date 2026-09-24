<?php
/**
 * IOCs: indicators (malicious/suspicious domains) per keyword.
 *
 * Sources: live current state, or the domains reported in saved report
 * snapshots. Exports: plain text (EDL / MISP freetext) and MISP event JSON.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/iocs.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$source = (string)($_GET['source'] ?? 'live');
if (!in_array($source, ['live', 'reports'], true)) {
    $source = 'live';
}
$severity = (string)($_GET['severity'] ?? 'malicious');
if (!in_array($severity, ['malicious', 'malicious_suspicious'], true)) {
    $severity = 'malicious';
}
$keywordId = (int)($_GET['keyword_id'] ?? 0);
$keywordId = $keywordId > 0 ? $keywordId : null;

// Validate keyword ownership when filtering.
$keywordName = '';
if ($keywordId !== null) {
    $chk = $db->prepare("SELECT keyword FROM keywords WHERE id = ? AND user_id = ? LIMIT 1");
    $chk->execute([$keywordId, $userId]);
    $keywordName = (string)($chk->fetchColumn() ?: '');
    if ($keywordName === '') {
        $keywordId = null;
    }
}

$rows = iocCollect($db, $userId, $source, $keywordId, $severity);

// ---------- Export (authenticated manual download) ----------
$export = (string)($_GET['export'] ?? '');
if ($export === 'txt' || $export === 'mispjson') {
    $scope = $keywordName !== '' ? $keywordName : 'all-keywords';
    $safe = preg_replace('/[^a-z0-9._-]+/i', '_', $scope);
    $date = gmdate('Ymd');
    if ($export === 'txt') {
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="iocs-' . $safe . '-' . $date . '.txt"');
        echo iocFormatTxt($rows);
    } else {
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="iocs-' . $safe . '-' . $date . '.json"');
        echo iocFormatMispJson($rows, $scope);
    }
    exit;
}

$groups = iocGroupByKeyword($rows);
$counts = ['malicious' => 0, 'suspicious' => 0];
foreach ($rows as $r) {
    $counts[$r['status']] = ($counts[$r['status']] ?? 0) + 1;
}
$uniqueTotal = count(iocUniqueDomains($rows));
$displayRows = array_slice($rows, 0, 1000);

// Keywords for the filter dropdown.
$kwStmt = $db->prepare("SELECT id, keyword FROM keywords WHERE user_id = ? ORDER BY keyword ASC");
$kwStmt->execute([$userId]);
$keywords = $kwStmt->fetchAll();

$qs = function (array $override = []) use ($source, $severity, $keywordId): string {
    $q = array_merge([
        'source' => $source,
        'severity' => $severity,
        'keyword_id' => $keywordId ?: 0,
    ], $override);
    return http_build_query($q);
};

$pageTitle = 'IOCs';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2>IOCs &mdash; indicators of compromise</h2>
        <span class="muted"><?= number_format($uniqueTotal) ?> unique domain(s)</span>
    </div>

    <p class="muted">
        Malicious/suspicious domains per keyword, ready to export as a plain-text list (EDL / MISP freetext)
        or as a MISP event JSON. A domain that matches several keywords appears in each list; the "all" view deduplicates.
    </p>

    <form method="GET" action="/iocs.php" class="section-actions" style="flex-wrap: wrap;">
        <label class="muted">Source
            <select name="source" class="browser-default compact" onchange="this.form.submit()">
                <option value="live" <?= $source === 'live' ? 'selected' : '' ?>>Live (current)</option>
                <option value="reports" <?= $source === 'reports' ? 'selected' : '' ?>>Generated reports</option>
            </select>
        </label>
        <label class="muted">Keyword
            <select name="keyword_id" class="browser-default compact" onchange="this.form.submit()">
                <option value="0">All keywords</option>
                <?php foreach ($keywords as $k): ?>
                    <option value="<?= (int)$k['id'] ?>" <?= $keywordId === (int)$k['id'] ? 'selected' : '' ?>><?= htmlspecialchars($k['keyword']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="muted">Severity
            <select name="severity" class="browser-default compact" onchange="this.form.submit()">
                <option value="malicious" <?= $severity === 'malicious' ? 'selected' : '' ?>>Malicious</option>
                <option value="malicious_suspicious" <?= $severity === 'malicious_suspicious' ? 'selected' : '' ?>>Malicious + Suspicious</option>
            </select>
        </label>
        <span class="muted">
            <strong><?= number_format($counts['malicious']) ?></strong> malicious
            <?php if ($severity === 'malicious_suspicious'): ?>
                &middot; <strong><?= number_format($counts['suspicious']) ?></strong> suspicious
            <?php endif; ?>
        </span>
    </form>

    <div class="section-actions">
        <a class="btn btn-small waves-effect" href="/iocs.php?<?= $qs(['export' => 'txt']) ?>"><i class="material-icons left">download</i>Download TXT</a>
        <a class="btn btn-small waves-effect" href="/iocs.php?<?= $qs(['export' => 'mispjson']) ?>"><i class="material-icons left">download</i>Download MISP JSON</a>
        <button type="button" class="btn btn-small btn-outline waves-effect" data-ioc-copy data-url="/iocs.php?<?= $qs(['export' => 'txt']) ?>"><i class="material-icons left">content_copy</i>Copy TXT</button>
        <?php if ($keywordName !== ''): ?>
            <span class="muted">Filtered to keyword <strong><?= htmlspecialchars($keywordName) ?></strong></span>
        <?php endif; ?>
    </div>

    <?php if (empty($rows)): ?>
        <p class="muted">No indicators for this filter. Mark domains <strong>Bad</strong> or run VirusTotal / abuse.ch on them (or generate a report) to populate this list.</p>
    <?php else: ?>
        <div class="muted" style="margin: 8px 0;">
            <?php foreach ($groups as $g): ?>
                <span class="tag-chip report" style="margin-right:6px;"><?= htmlspecialchars($g['keyword']) ?>: <?= count($g['rows']) ?></span>
            <?php endforeach; ?>
        </div>

        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Keyword</th>
                    <th>Status</th>
                    <th>Tag</th>
                    <th>VT</th>
                    <th>abuse.ch</th>
                    <th>First seen</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($displayRows as $r): ?>
                <tr>
                    <td><strong><?= htmlspecialchars($r['domain']) ?></strong></td>
                    <td><?= htmlspecialchars((string)$r['keyword']) ?></td>
                    <td>
                        <?php if ($r['status'] === 'malicious'): ?>
                            <span class="vt-badge vt-malicious">MALICIOUS</span>
                        <?php else: ?>
                            <span class="vt-badge vt-suspicious">SUSPICIOUS</span>
                        <?php endif; ?>
                    </td>
                    <td><?= $r['tag'] !== '' ? htmlspecialchars(strtoupper((string)$r['tag'])) : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= ($r['verdict'] ?? '') !== '' ? htmlspecialchars((string)$r['verdict']) : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= ($r['abusech_verdict'] ?? '') !== '' ? htmlspecialchars((string)$r['abusech_verdict']) : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= !empty($r['first_seen']) ? htmlspecialchars(substr(fmt_date((string)$r['first_seen']), 0, 10)) : '<span class="muted">&mdash;</span>' ?></td>
                    <td><?= !empty($r['creation_date']) ? htmlspecialchars(substr(fmt_date((string)$r['creation_date']), 0, 10)) : '<span class="muted">&mdash;</span>' ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php if (count($rows) > count($displayRows)): ?>
            <p class="muted">Showing the first <?= count($displayRows) ?> of <?= number_format(count($rows)) ?> row(s). The download includes all of them.</p>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
