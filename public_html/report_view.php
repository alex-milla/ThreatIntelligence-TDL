<?php
/**
 * Printable report (saved snapshot).
 *
 * Reports are generated from the Reports builder and stored (immutably) in
 * `report_history`. This page loads one by id, decodes the gzip-compressed
 * snapshot and renders it with all the WHOIS/VirusTotal data collected at
 * generation time. Designed to be printed (browser "Print / Save as PDF").
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    header('Location: /reports.php');
    exit;
}

$stmt = $db->prepare("SELECT title, group_name, filters, keywords, data, domains, created_at
    FROM report_history WHERE id = ? AND user_id = ? LIMIT 1");
$stmt->execute([$id, $userId]);
$row = $stmt->fetch();

$pageTitle = 'Report';

if (!$row) {
    http_response_code(404);
    require __DIR__ . '/templates/header.php';
    ?>
    <div class="card">
        <div class="card-head"><h2>Report not found</h2></div>
        <p class="muted">This report does not exist or does not belong to your account.</p>
        <a href="/reports.php" class="btn waves-effect"><i class="material-icons left">arrow_back</i>Back to Reports</a>
    </div>
    <?php
    require __DIR__ . '/templates/footer.php';
    exit;
}

$snapshot = [];
if (!empty($row['data'])) {
    $raw = @gzuncompress((string)$row['data']);
    if ($raw !== false) {
        $snapshot = json_decode($raw, true) ?: [];
    }
}

$report = is_array($snapshot['report'] ?? null) ? $snapshot['report'] : [];
$includedKeywords = is_array($snapshot['keywords'] ?? null) ? $snapshot['keywords'] : [];
$groupName = (string)($row['group_name'] ?? ($snapshot['group_name'] ?? ''));
$filterSummary = (string)($snapshot['filter_summary'] ?? '');
$reportTitle = (string)($row['title'] ?? '');
$generatedAt = fmt_date((string)($row['created_at'] ?? ($snapshot['generated_at'] ?? gmdate('Y-m-d H:i:s'))));
$truncated = !empty($snapshot['truncated']);
$maxRows = 2000;

// Grand totals from the per-keyword counters.
$totalDomains = 0;
$grandNew = 0;
$grandWatchlist = 0;
$grandTag = ['good' => 0, 'bad' => 0, 'observing' => 0, 'untagged' => 0];
$grandVt = ['malicious' => 0, 'suspicious' => 0, 'dga' => 0, 'clean' => 0];
foreach ($report as $data) {
    $c = $data['counts'] ?? [];
    $totalDomains += (int)($c['domains'] ?? 0);
    $grandNew += (int)($c['new'] ?? 0);
    $grandWatchlist += (int)($c['watchlist'] ?? 0);
    foreach ($grandTag as $t => $_) { $grandTag[$t] += (int)($c[$t] ?? 0); }
    foreach ($grandVt as $v => $_) { $grandVt[$v] += (int)($c[$v] ?? 0); }
}

$vtLabels = ['malicious' => 'MALICIOUS', 'dga' => 'DGA', 'suspicious' => 'SUSPICIOUS', 'clean' => 'CLEAN'];
$tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];

// Small helper: render the cached VirusTotal cell (verdict + engine counts).
function reportVtCell(array $r, array $vtLabels): string {
    if (($r['verdict'] ?? null) === null) {
        return '<span class="muted">Not checked</span>';
    }
    $val = (string)$r['verdict'];
    $badge = isset($vtLabels[$val])
        ? '<span class="vt-badge vt-' . $val . '">' . $vtLabels[$val] . '</span>'
        : '<span class="muted">' . htmlspecialchars($val) . '</span>';
    $detail = sprintf('M %d · S %d · H %d · U %d',
        (int)($r['malicious'] ?? 0), (int)($r['suspicious'] ?? 0),
        (int)($r['harmless'] ?? 0), (int)($r['undetected'] ?? 0));
    if ((int)($r['reputation'] ?? 0) !== 0) {
        $detail .= ' · rep ' . (int)$r['reputation'];
    }
    return '<div class="vt-cell">' . $badge . '<span class="vt-detail">' . htmlspecialchars($detail) . '</span></div>';
}

require __DIR__ . '/templates/header.php';
?>

<div class="report-toolbar no-print">
    <a href="/reports.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">arrow_back</i>Back to Reports</a>
    <button type="button" class="btn btn-small waves-effect" onclick="window.print()"><i class="material-icons left">print</i>Print / Save as PDF</button>
</div>

<div class="card report-card">
    <header class="report-cover">
        <div class="report-cover-brand">ThreatIntelligence-TDL</div>
        <h1>Domain Threat Report</h1>
        <?php if ($reportTitle !== ''): ?>
            <div class="report-cover-title"><?= htmlspecialchars($reportTitle) ?></div>
        <?php endif; ?>
        <div class="report-cover-sub">
            <?php if ($groupName !== ''): ?><span>Group: <strong><?= htmlspecialchars($groupName) ?></strong></span><?php endif; ?>
            <span>Filters: <strong><?= htmlspecialchars($filterSummary) ?></strong></span>
            <span>Generated: <strong><?= htmlspecialchars($generatedAt) ?></strong> (Europe/Madrid)</span>
        </div>
    </header>

    <?php if (empty($report)): ?>
        <p class="muted">This report has no domains.</p>
    <?php else: ?>

    <section class="report-kpis">
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($totalDomains) ?></span><span class="report-kpi-label">Domains</span></div>
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($grandNew) ?></span><span class="report-kpi-label">New</span></div>
        <div class="report-kpi danger"><span class="report-kpi-value"><?= number_format($grandVt['malicious']) ?></span><span class="report-kpi-label">Malicious</span></div>
        <div class="report-kpi warning"><span class="report-kpi-value"><?= number_format($grandVt['suspicious']) ?></span><span class="report-kpi-label">Suspicious</span></div>
        <div class="report-kpi good"><span class="report-kpi-value"><?= number_format($grandTag['good']) ?></span><span class="report-kpi-label">Good</span></div>
        <div class="report-kpi bad"><span class="report-kpi-value"><?= number_format($grandTag['bad']) ?></span><span class="report-kpi-label">Bad</span></div>
    </section>

    <div class="report-meta">
        <div><span class="report-meta-label">Keywords included</span> <?= count($report) ?></div>
        <div><span class="report-meta-label">Domains</span> <?= number_format($totalDomains) ?></div>
        <div><span class="report-meta-label">Filters</span> <?= htmlspecialchars($filterSummary) ?></div>
    </div>
    <div class="report-keywords">
        <?php foreach ($includedKeywords as $name): ?>
            <span class="report-keyword-chip"><?= htmlspecialchars((string)$name) ?></span>
        <?php endforeach; ?>
    </div>

    <h2 class="report-section-title">Summary</h2>
    <table class="striped report-table report-summary">
        <thead>
            <tr>
                <th>Keyword</th>
                <th class="num">Domains</th>
                <th class="num">New</th>
                <th class="num">Good</th>
                <th class="num">Bad</th>
                <th class="num">Observing</th>
                <th class="num">Untagged</th>
                <th class="num">Watchlist</th>
                <th class="num">Malicious</th>
                <th class="num">Suspicious</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($report as $data): $c = $data['counts'] ?? []; ?>
            <tr>
                <td><strong><?= htmlspecialchars((string)($data['keyword'] ?? '')) ?></strong></td>
                <td class="num"><?= number_format((int)($c['domains'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['new'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['good'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['bad'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['observing'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['untagged'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['watchlist'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['malicious'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['suspicious'] ?? 0)) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr>
                <th>Total</th>
                <th class="num"><?= number_format($totalDomains) ?></th>
                <th class="num"><?= number_format($grandNew) ?></th>
                <th class="num"><?= number_format($grandTag['good']) ?></th>
                <th class="num"><?= number_format($grandTag['bad']) ?></th>
                <th class="num"><?= number_format($grandTag['observing']) ?></th>
                <th class="num"><?= number_format($grandTag['untagged']) ?></th>
                <th class="num"><?= number_format($grandWatchlist) ?></th>
                <th class="num"><?= number_format($grandVt['malicious']) ?></th>
                <th class="num"><?= number_format($grandVt['suspicious']) ?></th>
            </tr>
        </tfoot>
    </table>

    <?php if ($truncated): ?>
        <p class="muted no-print">Some keyword sections were truncated to <?= number_format($maxRows) ?> domains each.</p>
    <?php endif; ?>

    <?php foreach ($report as $data): $c = $data['counts'] ?? []; ?>
        <section class="report-section">
            <h2 class="report-section-title report-keyword-title">
                <span class="report-keyword-name"><?= htmlspecialchars((string)($data['keyword'] ?? '')) ?></span>
                <span class="report-keyword-stats">
                    <span class="report-pill"><?= number_format((int)($c['domains'] ?? 0)) ?> domains</span>
                    <?php if ((int)($c['new'] ?? 0) > 0): ?><span class="report-pill new"><?= number_format((int)$c['new']) ?> new</span><?php endif; ?>
                    <?php if ((int)($c['malicious'] ?? 0) > 0): ?><span class="report-pill danger"><?= number_format((int)$c['malicious']) ?> malicious</span><?php endif; ?>
                    <?php if ((int)($c['suspicious'] ?? 0) > 0): ?><span class="report-pill warning"><?= number_format((int)$c['suspicious']) ?> suspicious</span><?php endif; ?>
                </span>
            </h2>

            <?php $rows = is_array($data['rows'] ?? null) ? $data['rows'] : []; ?>
            <?php if (empty($rows)): ?>
                <p class="muted">No domains in this section.</p>
            <?php else: ?>
            <table class="striped report-table report-detail">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>TLD</th>
                        <th>Source</th>
                        <th>First Seen</th>
                        <th>Created</th>
                        <th>Expiration</th>
                        <th>Registrar</th>
                        <th>Name Servers</th>
                        <th>WHOIS</th>
                        <th>Tag</th>
                        <th>VirusTotal</th>
                        <th>Watchlist</th>
                        <th>Hist.</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $r):
                        $tagVal = (string)($r['tag'] ?? '');
                        $tagCell = isset($tagLabels[$tagVal])
                            ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                            : '<span class="muted">&mdash;</span>';

                        $vtCell = reportVtCell($r, $vtLabels);

                        $creation = !empty($r['creation_date']) ? substr(fmt_date((string)$r['creation_date']), 0, 10) : '—';
                        $expiration = !empty($r['expiration_date']) ? substr(fmt_date((string)$r['expiration_date']), 0, 10) : '—';
                        $sourceLabel = ((string)($r['source'] ?? '') === 'ct') ? 'OpenINTEL' : 'CZDS';
                        $whoisStatus = (string)($r['whois_status'] ?? '');
                        $whoisCell = $whoisStatus === '' ? '<span class="muted">&mdash;</span>'
                            : '<span class="whois-status whois-' . htmlspecialchars($whoisStatus) . '">' . htmlspecialchars($whoisStatus) . '</span>';
                        $lastAnalysis = !empty($r['last_analysis_date']) ? substr(fmt_date((string)$r['last_analysis_date']), 0, 10) : '';
                        $ns = is_array($r['_ns'] ?? null) ? $r['_ns'] : [];
                        $firstSeen = !empty($r['first_seen']) ? fmt_date((string)$r['first_seen']) : '—';
                    ?>
                    <tr>
                        <td class="domain-cell"><?= htmlspecialchars((string)($r['domain'] ?? '')) ?></td>
                        <td><?= htmlspecialchars((string)($r['tld'] ?? '')) ?></td>
                        <td><?= htmlspecialchars($sourceLabel) ?></td>
                        <td><?= htmlspecialchars($firstSeen) ?></td>
                        <td><?= htmlspecialchars($creation) ?><?php if (!empty($r['_is_new'])): ?> <span class="badge-new">NEW</span><?php endif; ?></td>
                        <td><?= htmlspecialchars($expiration) ?></td>
                        <td><?= !empty($r['registrar']) ? htmlspecialchars((string)$r['registrar']) : '<span class="muted">&mdash;</span>' ?></td>
                        <td class="ns-cell"><?= !empty($ns) ? htmlspecialchars(implode(', ', $ns)) : '<span class="muted">&mdash;</span>' ?></td>
                        <td><?= $whoisCell ?></td>
                        <td><?= $tagCell ?></td>
                        <td><?= $vtCell ?><?php if ($lastAnalysis !== ''): ?><span class="vt-detail"><?= htmlspecialchars($lastAnalysis) ?></span><?php endif; ?></td>
                        <td><?= !empty($r['in_watchlist']) ? 'Yes' : '<span class="muted">No</span>' ?></td>
                        <td><?= !empty($r['is_historical']) ? 'Yes' : '<span class="muted">No</span>' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </section>
    <?php endforeach; ?>

    <footer class="report-foot">
        Generated by ThreatIntelligence-TDL on <?= htmlspecialchars($generatedAt) ?> — <?= number_format($totalDomains) ?> domain(s) across <?= count($report) ?> keyword(s).
    </footer>

    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
