<?php
/**
 * Printable report (saved snapshot) — threat-intelligence layout.
 *
 * Reports are generated from the Reports builder and stored (immutably) in
 * `report_history`. This page loads one by id, decodes the gzip-compressed
 * snapshot and renders it as a threat-intelligence report: an executive
 * summary, mutually-exclusive assessment KPIs, shared-infrastructure and
 * previous-report comparisons, and a triage table with an expandable detail
 * panel per domain (assessment, timeline, registration, reputation, detection
 * and raw data).
 *
 * All derived fields are computed from the stored snapshot via
 * `includes/report_present.php` (no schema changes), so older saved reports
 * render with the new layout too. Printing expands every domain detail.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_present.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    header('Location: /reports.php');
    exit;
}

$stmt = $db->prepare("SELECT title, group_id, group_name, filters, keywords, data, domains, created_at
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
$refUtc = (string)($snapshot['generated_at'] ?? ($row['created_at'] ?? gmdate('Y-m-d H:i:s')));
$truncated = !empty($snapshot['truncated']);
$maxRows = 2000;
$rules = reportReviewRules($db);
$printMode = isset($_GET['print']) && $_GET['print'] === '1';

$statusSymbol = ['malicious' => '●', 'suspicious' => '⚠', 'review_required' => '⚠', 'benign' => '✓', 'unknown' => '○'];
$repSymbol = ['malicious' => '●', 'suspicious' => '⚠', 'dga' => '⚠', 'clean' => '✓', 'not_checked' => '○'];

$tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];

// ---------- Derive the presentation model + aggregates ----------
$sections = [];
$firstSeenTs = null;
$lastSeenTs = null;
foreach ($report as $data) {
    $kw = (string)($data['keyword'] ?? '');
    $counts = $data['counts'] ?? [];
    $rows = is_array($data['rows'] ?? null) ? $data['rows'] : [];
    $enriched = [];
    foreach ($rows as $r) {
        $age = reportDomainAge($r['creation_date'] ?? null, $refUtc);
        $status = reportDomainStatus($r, $rules);
        $rep = reportReputation($r);
        $avail = reportAvailability($r);
        $enriched[] = [
            'row'      => $r,
            'age'      => $age,
            'status'   => $status,
            'rep'      => $rep,
            'why'      => reportWhyFlagged($r),
            'avail'    => $avail,
            'risk'     => reportRiskAssessment($r, $status, $avail),
            'timeline' => reportTimeline($r, $refUtc),
        ];
        $fs = $r['first_seen'] ?? ($r['discovered_at'] ?? null);
        if ($fs && ($t = strtotime((string)$fs)) !== false && ($firstSeenTs === null || $t < $firstSeenTs)) {
            $firstSeenTs = $t;
        }
        if (!empty($r['discovered_at']) && ($t = strtotime((string)$r['discovered_at'])) !== false && ($lastSeenTs === null || $t > $lastSeenTs)) {
            $lastSeenTs = $t;
        }
    }
    $sections[] = ['keyword' => $kw, 'counts' => $counts, 'rows' => $enriched];
}

$currentAgg = reportAggregateReport($report, $rules, $refUtc);
$statusCounts = $currentAgg['status'];
$totalDomains = $currentAgg['domains'];
$newCount = $currentAgg['new'];
$watchlistCount = $currentAgg['watchlist'];
$notCheckedVt = $currentAgg['not_checked_vt'];

// Grand totals per Summary column (tags + VirusTotal verdicts).
$grand = ['good' => 0, 'bad' => 0, 'observing' => 0, 'untagged' => 0, 'malicious' => 0, 'suspicious' => 0];
foreach ($sections as $sec) {
    $c = $sec['counts'];
    foreach ($grand as $k => $_) {
        if (isset($c[$k])) { $grand[$k] += (int)$c[$k]; }
    }
}

// ---------- Shared infrastructure (correlation of collected data) ----------
$shared = reportSharedInfrastructure($sections);
$hasShared = !empty($shared['nameservers']) || !empty($shared['registrars']);

// ---------- Previous report comparison (same keyword set + group) ----------
$prevSnapshot = null;
$prevId = 0;
$prevCreated = '';
$currentKeywords = is_array($snapshot['keywords'] ?? null) ? $snapshot['keywords'] : [];
sort($currentKeywords);
$gid = $row['group_id'] ?? null;
$prevStmt = $db->prepare("SELECT id, group_id, keywords, data, created_at
    FROM report_history WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT 20");
$prevStmt->execute([$userId, $id]);
foreach ($prevStmt->fetchAll() as $p) {
    $pkw = json_decode((string)$p['keywords'], true) ?: [];
    sort($pkw);
    $sameGroup = (($p['group_id'] === null && ($gid === null || $gid === ''))
        || ((string)$p['group_id'] === (string)$gid));
    if (!$sameGroup || $pkw !== $currentKeywords) {
        continue;
    }
    $raw2 = @gzuncompress((string)$p['data']);
    $cand = $raw2 !== false ? (json_decode($raw2, true) ?: null) : null;
    if ($cand && !empty($cand['report'])) {
        $prevSnapshot = $cand;
        $prevId = (int)$p['id'];
        $prevCreated = (string)$p['created_at'];
    }
    break;
}
$prevAgg = $prevSnapshot
    ? reportAggregateReport($prevSnapshot['report'] ?? [], $rules, (string)($prevSnapshot['generated_at'] ?? ''))
    : null;
$delta = function (int $old, int $new): string {
    $d = $new - $old;
    return $d > 0 ? '+' . $d : ($d < 0 ? (string)$d : '0');
};

// ---------- Executive summary notes (never "no verdict" => "safe") ----------
$execNotes = [];
$execNotes[] = count($sections) === 1
    ? 'All domains match the monitored keyword "' . (string)($sections[0]['keyword'] ?? '') . '".'
    : 'Domains match ' . count($sections) . ' monitored keywords.';
if ($newCount > 0) {
    $execNotes[] = $newCount . ' were recently registered.';
}
$execNotes[] = $statusCounts['malicious'] > 0
    ? $statusCounts['malicious'] . ' confirmed malicious (VirusTotal or analyst).'
    : 'No confirmed malicious verdict.';
$execNotes[] = $notCheckedVt > 0
    ? 'No external reputation verdict was available for ' . $notCheckedVt . ' domain(s) at generation time.'
    : 'Every domain has a cached VirusTotal verdict.';
if ($watchlistCount > 0) {
    $execNotes[] = $watchlistCount . ' domain(s) are in the watchlist.';
}
$fmtTs = fn($t) => $t ? fmt_date(gmdate('Y-m-d H:i:s', $t)) : '—';

require __DIR__ . '/templates/header.php';

if ($printMode) {
    require __DIR__ . '/templates/report_print.php';
    require __DIR__ . '/templates/footer.php';
    exit;
}
?>

<div class="report-toolbar no-print">
    <a href="/reports.php" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">arrow_back</i>Back to Reports</a>
    <button type="button" class="btn btn-small btn-outline waves-effect" onclick="toggleAllDetails(true)"><i class="material-icons left">unfold_more</i>Expand all</button>
    <button type="button" class="btn btn-small btn-outline waves-effect" onclick="toggleAllDetails(false)"><i class="material-icons left">unfold_less</i>Collapse all</button>
    <a href="/report_view.php?id=<?= (int)$id ?>&print=1" class="btn btn-small waves-effect"><i class="material-icons left">picture_as_pdf</i>Print / PDF</a>
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

    <section class="report-exec">
        <h2 class="report-exec-title">Executive Summary</h2>
        <div class="report-exec-stats">
            <div><span class="report-exec-num"><?= number_format($totalDomains) ?></span><span class="report-exec-label">domains detected</span></div>
            <div><span class="report-exec-num"><?= number_format($statusCounts['review_required']) ?></span><span class="report-exec-label">require review</span></div>
            <div><span class="report-exec-num"><?= number_format($statusCounts['malicious']) ?></span><span class="report-exec-label">confirmed malicious</span></div>
        </div>
        <ul class="report-exec-notes">
            <?php foreach ($execNotes as $note): ?>
                <li><?= htmlspecialchars($note) ?></li>
            <?php endforeach; ?>
        </ul>
    </section>

    <section class="report-kpis">
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($totalDomains) ?></span><span class="report-kpi-label">Domains</span></div>
        <div class="report-kpi warning"><span class="report-kpi-value"><?= number_format($statusCounts['review_required']) ?></span><span class="report-kpi-label">Review required</span></div>
        <div class="report-kpi danger"><span class="report-kpi-value"><?= number_format($statusCounts['malicious']) ?></span><span class="report-kpi-label">Confirmed malicious</span></div>
        <div class="report-kpi warning"><span class="report-kpi-value"><?= number_format($statusCounts['suspicious']) ?></span><span class="report-kpi-label">Suspicious</span></div>
        <div class="report-kpi good"><span class="report-kpi-value"><?= number_format($statusCounts['benign']) ?></span><span class="report-kpi-label">Confirmed benign</span></div>
        <div class="report-kpi"><span class="report-kpi-value"><?= number_format($statusCounts['unknown']) ?></span><span class="report-kpi-label">Unknown / not checked</span></div>
    </section>

    <div class="report-meta">
        <div><span class="report-meta-label">Keywords included</span> <?= count($sections) ?></div>
        <div><span class="report-meta-label">Domains</span> <?= number_format($totalDomains) ?></div>
        <div><span class="report-meta-label">First seen</span> <?= htmlspecialchars($fmtTs($firstSeenTs)) ?></div>
        <div><span class="report-meta-label">Last seen</span> <?= htmlspecialchars($fmtTs($lastSeenTs)) ?></div>
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
                <th class="num">Review</th>
                <th class="num">Good</th>
                <th class="num">Bad</th>
                <th class="num">Observing</th>
                <th class="num">Untagged</th>
                <th class="num">Malicious</th>
                <th class="num">Suspicious</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($sections as $sec): $c = $sec['counts']; $review = 0;
                foreach ($sec['rows'] as $er) { if ($er['status'] === 'review_required') { $review++; } } ?>
            <tr>
                <td><strong><?= htmlspecialchars($sec['keyword']) ?></strong></td>
                <td class="num"><?= number_format((int)($c['domains'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['new'] ?? 0)) ?></td>
                <td class="num"><?= number_format($review) ?></td>
                <td class="num"><?= number_format((int)($c['good'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['bad'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['observing'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['untagged'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['malicious'] ?? 0)) ?></td>
                <td class="num"><?= number_format((int)($c['suspicious'] ?? 0)) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr>
                <th>Total</th>
                <th class="num"><?= number_format($totalDomains) ?></th>
                <th class="num"><?= number_format($newCount) ?></th>
                <th class="num"><?= number_format($statusCounts['review_required']) ?></th>
                <th class="num"><?= number_format($grand['good']) ?></th>
                <th class="num"><?= number_format($grand['bad']) ?></th>
                <th class="num"><?= number_format($grand['observing']) ?></th>
                <th class="num"><?= number_format($grand['untagged']) ?></th>
                <th class="num"><?= number_format($grand['malicious']) ?></th>
                <th class="num"><?= number_format($grand['suspicious']) ?></th>
            </tr>
        </tfoot>
    </table>

    <?php if ($hasShared): ?>
        <h2 class="report-section-title">Shared infrastructure</h2>
        <div class="report-shared">
            <?php foreach ($shared['nameservers'] as $ns => $doms): ?>
                <div class="shared-item">
                    <span class="shared-value"><?= htmlspecialchars($ns) ?></span>
                    <span class="shared-count"><?= count($doms) ?> domains</span>
                    <span class="shared-domains"><?= htmlspecialchars(implode(', ', array_slice($doms, 0, 8))) ?><?= count($doms) > 8 ? ' …' : '' ?></span>
                </div>
            <?php endforeach; ?>
            <?php foreach ($shared['registrars'] as $reg => $doms): ?>
                <div class="shared-item">
                    <span class="shared-value"><?= htmlspecialchars($reg) ?></span>
                    <span class="shared-count"><?= count($doms) ?> domains (registrar)</span>
                    <span class="shared-domains"><?= htmlspecialchars(implode(', ', array_slice($doms, 0, 8))) ?><?= count($doms) > 8 ? ' …' : '' ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <p class="muted">Domains sharing the same name server or registrar. Correlation of already-collected data (no external source).</p>
    <?php endif; ?>

    <?php if ($prevAgg !== null): ?>
        <h2 class="report-section-title">Change since previous report</h2>
        <table class="striped report-table report-compare">
            <thead>
                <tr><th>Metric</th><th class="num">Previous</th><th class="num">Current</th><th class="num">Change</th></tr>
            </thead>
            <tbody>
                <?php
                $compareRows = [
                    'Domains' => [$prevAgg['domains'], $totalDomains],
                    'New' => [$prevAgg['new'], $newCount],
                    'Review required' => [$prevAgg['status']['review_required'], $statusCounts['review_required']],
                    'Confirmed malicious' => [$prevAgg['status']['malicious'], $statusCounts['malicious']],
                    'Suspicious' => [$prevAgg['status']['suspicious'], $statusCounts['suspicious']],
                    'Confirmed benign' => [$prevAgg['status']['benign'], $statusCounts['benign']],
                ];
                foreach ($compareRows as $label => $pair): ?>
                <tr>
                    <td><?= htmlspecialchars($label) ?></td>
                    <td class="num"><?= number_format($pair[0]) ?></td>
                    <td class="num"><?= number_format($pair[1]) ?></td>
                    <td class="num"><?= htmlspecialchars($delta((int)$pair[0], (int)$pair[1])) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p class="muted">Compared with report #<?= (int)$prevId ?> generated <?= htmlspecialchars(fmt_date($prevCreated)) ?> (same keyword set and group).</p>
    <?php endif; ?>

    <h2 class="report-section-title">Detections</h2>

    <?php if ($truncated): ?>
        <p class="muted no-print">Some keyword sections were truncated to <?= number_format($maxRows) ?> domains each.</p>
    <?php endif; ?>

    <?php foreach ($sections as $sec): $c = $sec['counts']; ?>
        <section class="report-section">
            <h2 class="report-section-title report-keyword-title">
                <span class="report-keyword-name"><?= htmlspecialchars($sec['keyword']) ?></span>
                <span class="report-keyword-stats">
                    <span class="report-pill"><?= number_format((int)($c['domains'] ?? 0)) ?> domains</span>
                    <?php if ((int)($c['new'] ?? 0) > 0): ?><span class="report-pill new"><?= number_format((int)$c['new']) ?> new</span><?php endif; ?>
                    <?php if ((int)($c['malicious'] ?? 0) > 0): ?><span class="report-pill danger"><?= number_format((int)$c['malicious']) ?> malicious</span><?php endif; ?>
                    <?php if ((int)($c['suspicious'] ?? 0) > 0): ?><span class="report-pill warning"><?= number_format((int)$c['suspicious']) ?> suspicious</span><?php endif; ?>
                </span>
            </h2>

            <?php if (empty($sec['rows'])): ?>
                <p class="muted">No domains in this section.</p>
            <?php else: ?>
            <table class="striped report-table report-triage">
                <thead>
                    <tr>
                        <th>Assessment</th>
                        <th>Domain</th>
                        <th>Source</th>
                        <th>First seen</th>
                        <th>Age</th>
                        <th>Why flagged</th>
                        <th>Reputation</th>
                        <th class="no-print"></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($sec['rows'] as $er):
                        $r = $er['row'];
                        $status = $er['status'];
                        $rep = $er['rep'];
                        $risk = $er['risk'];
                        $whois = $er['avail']['whois'];
                        $ns = is_array($r['_ns'] ?? null) ? $r['_ns'] : [];
                        $sourceLabel = ((string)($r['source'] ?? '') === 'ct') ? 'OpenINTEL' : 'CZDS';
                        $firstSeen = !empty($r['first_seen']) ? fmt_date((string)$r['first_seen']) : '—';
                        $discovered = !empty($r['discovered_at']) ? fmt_date((string)$r['discovered_at']) : '—';
                        $created = !empty($r['creation_date']) ? substr(fmt_date((string)$r['creation_date']), 0, 10) : '—';
                        $expiration = !empty($r['expiration_date']) ? substr(fmt_date((string)$r['expiration_date']), 0, 10) : '—';
                        $tagVal = (string)($r['tag'] ?? '');
                        $tagCell = isset($tagLabels[$tagVal])
                            ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                            : '<span class="muted">&mdash;</span>';
                        $rawJson = htmlspecialchars(json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                    ?>
                    <tr class="triage-row">
                        <td><span class="status-pill status-<?= htmlspecialchars($status) ?>"><?= htmlspecialchars(reportStatusLabel($status)) ?></span></td>
                        <td class="domain-cell"><?= htmlspecialchars((string)($r['domain'] ?? '')) ?><?php if (!empty($r['_is_new'])): ?> <span class="badge-new">NEW</span><?php endif; ?></td>
                        <td><?= htmlspecialchars($sourceLabel) ?></td>
                        <td><?= htmlspecialchars($firstSeen) ?></td>
                        <td><?= htmlspecialchars(reportAgeLabel($er['age'])) ?></td>
                        <td><?= htmlspecialchars($er['why']) ?></td>
                        <td><span class="rep-pill rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?><span class="rep-detail"><?= htmlspecialchars($rep['detail']) ?></span><?php endif; ?></td>
                        <td class="no-print"><button type="button" class="btn btn-small btn-outline waves-effect detail-toggle" onclick="toggleDetail(this)" aria-expanded="false"><i class="material-icons left">expand_more</i>Details</button></td>
                    </tr>
                    <tr class="domain-detail-row" style="display:none;">
                        <td colspan="8">
                            <div class="domain-detail">
                                <div class="dd-grid">
                                    <div class="dd-block">
                                        <h4>Assessment</h4>
                                        <dl class="dd-list">
                                            <div><dt>Risk</dt><dd><span class="risk-pill risk-<?= htmlspecialchars($risk['risk']) ?>"><?= htmlspecialchars(ucfirst($risk['risk'])) ?></span></dd></div>
                                            <div><dt>Confidence</dt><dd><?= htmlspecialchars(ucfirst($risk['confidence'])) ?></dd></div>
                                        </dl>
                                        <ul class="dd-findings">
                                            <?php foreach ($risk['reasons'] as $reason): ?>
                                                <li><?= htmlspecialchars($reason) ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                    <div class="dd-block">
                                        <h4>Timeline</h4>
                                        <ul class="report-timeline">
                                            <?php foreach ($er['timeline'] as $ev): ?>
                                                <li><span class="tl-dot"></span><span class="tl-date"><?= htmlspecialchars(fmt_date((string)$ev['at'])) ?></span><span class="tl-label"><?= htmlspecialchars($ev['label']) ?></span><span class="tl-source muted"><?= htmlspecialchars($ev['source']) ?></span></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                    <div class="dd-block">
                                        <h4>Registration</h4>
                                        <dl class="dd-list">
                                            <div><dt>Registrar</dt><dd><?= !empty($r['registrar']) ? htmlspecialchars((string)$r['registrar']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                            <div><dt>Name servers</dt><dd><?= !empty($ns) ? htmlspecialchars(implode(', ', $ns)) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                            <div><dt>WHOIS</dt><dd><span class="avail avail-<?= htmlspecialchars($whois['state']) ?>"><?= htmlspecialchars($whois['label']) ?></span></dd></div>
                                            <div><dt>Source</dt><dd><?= !empty($r['whois_source']) ? htmlspecialchars((string)$r['whois_source']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                            <div><dt>Updated</dt><dd><?= !empty($r['whois_updated_at']) ? htmlspecialchars(fmt_date((string)$r['whois_updated_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        </dl>
                                    </div>
                                    <div class="dd-block">
                                        <h4>Reputation</h4>
                                        <dl class="dd-list">
                                            <div><dt>VirusTotal</dt><dd><span class="rep-pill rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?> <span class="muted"><?= htmlspecialchars($rep['detail']) ?></span><?php endif; ?></dd></div>
                                            <div><dt>Last analysis</dt><dd><?= htmlspecialchars(reportFormatDate($r['last_analysis_date'] ?? null)) ?></dd></div>
                                            <div><dt>Checked</dt><dd><?= !empty($r['vt_checked_at']) ? htmlspecialchars(fmt_date((string)$r['vt_checked_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                            <div><dt>Tag</dt><dd><?= $tagCell ?></dd></div>
                                            <div><dt>Watchlist</dt><dd><?= !empty($r['in_watchlist']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
                                        </dl>
                                    </div>
                                    <div class="dd-block">
                                        <h4>Detection</h4>
                                        <dl class="dd-list">
                                            <div><dt>Keyword</dt><dd><?= htmlspecialchars($sec['keyword']) ?></dd></div>
                                            <div><dt>Source</dt><dd><?= htmlspecialchars($sourceLabel) ?></dd></div>
                                            <div><dt>Historical</dt><dd><?= !empty($r['is_historical']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
                                            <?php if (!empty($r['tag_note'])): ?>
                                                <div><dt>Analyst note</dt><dd><?= htmlspecialchars((string)$r['tag_note']) ?></dd></div>
                                            <?php endif; ?>
                                        </dl>
                                        <ul class="dd-findings">
                                            <?php foreach (reportFindings($r, $sec['keyword'], $er['age']) as $f): ?>
                                                <li class="finding-<?= htmlspecialchars($f['severity']) ?>"><strong><?= htmlspecialchars($f['label']) ?></strong><?= $f['value'] !== '' ? ': <span class="muted">' . htmlspecialchars((string)$f['value']) . '</span>' : '' ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                </div>
                                <details class="dd-raw">
                                    <summary>Raw data</summary>
                                    <pre><?= $rawJson ?></pre>
                                </details>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </section>
    <?php endforeach; ?>

    <footer class="report-foot">
        Generated by ThreatIntelligence-TDL on <?= htmlspecialchars($generatedAt) ?> — <?= number_format($totalDomains) ?> domain(s) across <?= count($sections) ?> keyword(s).
        Filters: <?= htmlspecialchars($filterSummary) ?>.
        Sources: WHOIS/RDAP + VirusTotal only (DNS, passive DNS, TLS and IP/ASN are not integrated).
    </footer>

    <?php endif; ?>
</div>

<script>
// Expand/collapse a single domain detail row.
function toggleDetail(btn) {
    var row = btn.closest('tr');
    if (!row) return;
    var detail = row.nextElementSibling;
    if (!detail || !detail.classList.contains('domain-detail-row')) return;
    var open = detail.style.display === 'none' || detail.style.display === '';
    detail.style.display = open ? 'table-row' : 'none';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}
// Expand/collapse every detail row.
function toggleAllDetails(open) {
    document.querySelectorAll('.domain-detail-row').forEach(function (r) {
        r.style.display = open ? 'table-row' : 'none';
    });
    document.querySelectorAll('.detail-toggle').forEach(function (b) {
        b.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
}
// Always print with every detail expanded.
window.addEventListener('beforeprint', function () {
    document.querySelectorAll('.domain-detail-row').forEach(function (r) { r.style.display = 'table-row'; });
    document.querySelectorAll('details.dd-raw').forEach(function (d) { d.open = true; });
});
window.addEventListener('afterprint', function () {
    document.querySelectorAll('.domain-detail-row').forEach(function (r) { r.style.display = 'none'; });
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
