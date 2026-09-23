<?php
/**
 * Dedicated print / PDF document layout for a saved report.
 *
 * Rendered by report_view.php when ?print=1. Shares the same derived data as the
 * screen view; this template only lays it out as an A4 portrait technical
 * document: cover + executive summary, a compact triage table per keyword, and
 * an appendix with the full per-domain detail (including raw data). It uses its
 * own light palette so it prints identically regardless of the app theme.
 */
?>
<div class="rp">
    <div class="rp-toolbar" data-pagedjs-ignore>
        <button type="button" onclick="closePrintWindow()">Close</button>
        <a href="/report_view.php?id=<?= (int)$id ?>&print=1<?= empty($showRaw) ? '&raw=1' : '' ?>"><?= empty($showRaw) ? 'Include raw data' : 'Hide raw data' ?></a>
        <button type="button" onclick="window.print()">Print / Save as PDF</button>
    </div>

    <header class="rp-cover<?= $totalDomains > 8 ? ' rp-break' : '' ?>">
        <div class="rp-brand">ThreatIntelligence-TDL<?php if ($tlp !== ''): ?><span class="rp-tlp"><?= htmlspecialchars($tlp) ?></span><?php endif; ?></div>
        <h1>Domain Threat Report</h1>
        <?php if ($reportTitle !== ''): ?><div class="rp-subtitle"><?= htmlspecialchars($reportTitle) ?></div><?php endif; ?>
        <div class="rp-meta">
            <?php if ($groupName !== ''): ?><span><b>Group:</b> <?= htmlspecialchars($groupName) ?></span><?php endif; ?>
            <span><b>Filters:</b> <?= htmlspecialchars($filterSummary) ?></span>
            <span><b>Generated:</b> <?= htmlspecialchars($generatedAt) ?> (Europe/Madrid)</span>
        </div>

        <div class="rp-exec">
            <h2>Executive Summary</h2>
            <ul class="rp-notes">
                <?php foreach ($execNotes as $note): ?><li><?= htmlspecialchars($note) ?></li><?php endforeach; ?>
            </ul>
        </div>

        <div class="rp-kpis">
            <div><span class="n"><?= number_format($totalDomains) ?></span><span class="l">Domains</span></div>
            <div><span class="n"><?= number_format($statusCounts['review_required']) ?></span><span class="l">Review required</span></div>
            <div><span class="n"><?= number_format($statusCounts['malicious']) ?></span><span class="l">Malicious</span></div>
            <div><span class="n"><?= number_format($statusCounts['suspicious']) ?></span><span class="l">Suspicious</span></div>
            <div><span class="n"><?= number_format($statusCounts['benign']) ?></span><span class="l">Benign</span></div>
            <div><span class="n"><?= number_format($statusCounts['unknown']) ?></span><span class="l">Unknown</span></div>
        </div>

        <div class="rp-meta rp-meta-secondary">
            <span><b>Keywords:</b> <?= count($sections) ?></span>
            <span><b>First seen:</b> <?= htmlspecialchars($fmtTs($firstSeenTs)) ?></span>
            <span><b>Last seen:</b> <?= htmlspecialchars($fmtTs($lastSeenTs)) ?></span>
        </div>
    </header>

    <?php if ($hasShared): ?>
        <section class="rp-section">
            <h2>Shared infrastructure</h2>
            <table class="rp-table">
                <thead><tr><th>Shared value</th><th>Kind</th><th class="num">Domains</th><th>Domains</th></tr></thead>
                <tbody>
                    <?php foreach ($shared['nameservers'] as $ns => $doms): ?>
                        <tr><td><?= htmlspecialchars($ns) ?></td><td>Name server</td><td class="num"><?= count($doms) ?></td><td><?= htmlspecialchars(implode(', ', $doms)) ?></td></tr>
                    <?php endforeach; ?>
                    <?php foreach ($shared['registrars'] as $reg => $doms): ?>
                        <tr><td><?= htmlspecialchars($reg) ?></td><td>Registrar</td><td class="num"><?= count($doms) ?></td><td><?= htmlspecialchars(implode(', ', $doms)) ?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>
    <?php endif; ?>

    <?php if ($prevAgg !== null): ?>
        <section class="rp-section">
            <h2>Change since previous report</h2>
            <table class="rp-table">
                <thead><tr><th>Metric</th><th class="num">Previous</th><th class="num">Current</th><th class="num">Change</th></tr></thead>
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
                        <tr><td><?= htmlspecialchars($label) ?></td><td class="num"><?= number_format($pair[0]) ?></td><td class="num"><?= number_format($pair[1]) ?></td><td class="num"><?= htmlspecialchars($delta((int)$pair[0], (int)$pair[1])) ?></td></tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p class="rp-note">Compared with report #<?= (int)$prevId ?> generated <?= htmlspecialchars(fmt_date($prevCreated)) ?> (same keyword set and group).</p>
        </section>
    <?php endif; ?>

    <section class="rp-section">
        <h2>Detections</h2>
        <?php foreach ($sections as $sec): $c = $sec['counts']; ?>
            <div class="rp-kw">
                <h3>Keyword: <?= htmlspecialchars($sec['keyword']) ?> <span class="rp-muted">(<?= number_format((int)($c['domains'] ?? 0)) ?> domains)</span></h3>
                <?php if (empty($sec['rows'])): ?>
                    <p class="rp-note">No domains in this section.</p>
                <?php else: ?>
                <table class="rp-table">
                    <thead>
                        <tr>
                            <th>Assessment</th>
                            <th>Domain</th>
                            <th>Age</th>
                            <th>First seen</th>
                            <th>Why flagged</th>
                            <th>Reputation</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($sec['rows'] as $er): $r = $er['row']; $status = $er['status']; $rep = $er['rep']; $repOtx = reportOtx($r); ?>
                        <tr>
                            <td><span class="rp-status rp-<?= htmlspecialchars($status) ?>"><?= htmlspecialchars($statusSymbol[$status] ?? '') ?> <?= htmlspecialchars(reportStatusLabel($status)) ?></span></td>
                            <td class="rp-domain-name"><?= reportHighlightKeyword((string)($r['domain'] ?? ''), (string)$sec['keyword']) ?><?= reportTldBadge((string)($r['domain'] ?? '')) ?><?php if (!empty($r['_is_new'])): ?> <span class="rp-new">NEW</span><?php endif; ?></td>
                            <td class="<?= htmlspecialchars(reportAgeClass($er['age'])) ?>"><?= htmlspecialchars(reportAgeLabel($er['age'])) ?></td>
                            <td><?= !empty($r['first_seen']) ? htmlspecialchars(fmt_date((string)$r['first_seen'])) : '—' ?></td>
                            <td><?= htmlspecialchars($er['why']) ?></td>
                            <td><span class="rp-rep rp-rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($repSymbol[$rep['state']] ?? '') ?> <?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?> <span class="rp-muted">(<?= htmlspecialchars($rep['detail']) ?>)</span><?php endif; ?><?php if (in_array($repOtx['state'], ['malicious', 'suspicious', 'clean'], true)): ?> <span class="rp-rep rp-rep-<?= htmlspecialchars($repOtx['state']) ?>">OTX <?= htmlspecialchars($repOtx['label']) ?></span><?php endif; ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </section>

    <section class="rp-section rp-appendix">
        <h2>Appendix A &mdash; Domain details</h2>
        <?php foreach ($sections as $sec): foreach ($sec['rows'] as $er):
            $r = $er['row'];
            $status = $er['status'];
            $rep = $er['rep'];
            $repOtx = reportOtx($r);
            $risk = $er['risk'];
            $whois = $er['avail']['whois'];
            $ns = is_array($r['_ns'] ?? null) ? $r['_ns'] : [];
            $tagVal = (string)($r['tag'] ?? '');
            $rawJson = htmlspecialchars(json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        ?>
        <div class="rp-domain <?= htmlspecialchars($er['sev']) ?>">
            <h3>
                <span class="rp-domain-name"><?= reportHighlightKeyword((string)($r['domain'] ?? ''), (string)$sec['keyword']) ?></span><?= reportTldBadge((string)($r['domain'] ?? '')) ?>
                <span class="rp-status rp-<?= htmlspecialchars($status) ?>"><?= htmlspecialchars($statusSymbol[$status] ?? '') ?> <?= htmlspecialchars(reportStatusLabel($status)) ?></span>
                <span class="rp-muted">Keyword: <?= htmlspecialchars($sec['keyword']) ?> &middot; Age: <?= htmlspecialchars(reportAgeLabel($er['age'])) ?> &middot; Risk: <?= htmlspecialchars(ucfirst($risk['risk'])) ?> &middot; Confidence: <?= htmlspecialchars(ucfirst($risk['confidence'])) ?></span>
            </h3>

            <div class="rp-dd">
                <div class="rp-dd-block">
                    <h4>Timing</h4>
                    <dl>
                        <div><dt>First seen</dt><dd><?= !empty($r['first_seen']) ? htmlspecialchars(fmt_date((string)$r['first_seen'])) : '—' ?></dd></div>
                        <div><dt>Discovered</dt><dd><?= !empty($r['discovered_at']) ? htmlspecialchars(fmt_date((string)$r['discovered_at'])) : '—' ?></dd></div>
                        <div><dt>Created</dt><dd><?= htmlspecialchars(reportFormatDate($r['creation_date'] ?? null)) ?></dd></div>
                        <div><dt>Age</dt><dd><?= htmlspecialchars(reportAgeLabel($er['age'])) ?></dd></div>
                        <div><dt>Expiration</dt><dd><?= htmlspecialchars(reportFormatDate($r['expiration_date'] ?? null)) ?></dd></div>
                    </dl>
                </div>
                <div class="rp-dd-block">
                    <h4>Registration</h4>
                    <dl>
                        <div><dt>Registrar</dt><dd><?= !empty($r['registrar']) ? htmlspecialchars((string)$r['registrar']) : '—' ?></dd></div>
                        <div><dt>Name servers</dt><dd><?= !empty($ns) ? htmlspecialchars(implode(', ', $ns)) : '—' ?></dd></div>
                        <div><dt>WHOIS</dt><dd><?= htmlspecialchars($whois['label']) ?></dd></div>
                        <div><dt>Source</dt><dd><?= !empty($r['whois_source']) ? htmlspecialchars((string)$r['whois_source']) : '—' ?></dd></div>
                        <div><dt>Updated</dt><dd><?= htmlspecialchars(reportFormatDate($r['whois_updated_at'] ?? null)) ?></dd></div>
                    </dl>
                </div>
                <div class="rp-dd-block">
                    <h4>Reputation</h4>
                    <dl>
                        <div><dt>VirusTotal</dt><dd><span class="rp-rep rp-rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($repSymbol[$rep['state']] ?? '') ?> <?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?> (<?= htmlspecialchars($rep['detail']) ?>)<?php endif; ?></dd></div>
                        <div><dt>AlienVault OTX</dt><dd><span class="rp-rep rp-rep-<?= htmlspecialchars($repOtx['state']) ?>"><?= htmlspecialchars($repSymbol[$repOtx['state']] ?? '') ?> <?= htmlspecialchars($repOtx['label']) ?></span><?php if ($repOtx['detail'] !== ''): ?> (<?= htmlspecialchars($repOtx['detail']) ?>)<?php endif; ?></dd></div>
                        <div><dt>Last analysis</dt><dd><?= htmlspecialchars(reportFormatDate($r['last_analysis_date'] ?? null)) ?></dd></div>
                        <div><dt>Checked</dt><dd><?= htmlspecialchars(reportFormatDate($r['vt_checked_at'] ?? null)) ?></dd></div>
                        <div><dt>Tag</dt><dd><?= $tagVal !== '' ? htmlspecialchars(strtoupper($tagVal)) : '—' ?></dd></div>
                        <div><dt>Watchlist</dt><dd><?= !empty($r['in_watchlist']) ? 'Yes' : 'No' ?></dd></div>
                    </dl>
                </div>
                <div class="rp-dd-block">
                    <h4>Assessment</h4>
                    <dl>
                        <div><dt>Risk</dt><dd><?= htmlspecialchars(ucfirst($risk['risk'])) ?></dd></div>
                        <div><dt>Confidence</dt><dd><?= htmlspecialchars(ucfirst($risk['confidence'])) ?></dd></div>
                    </dl>
                    <ul class="rp-reasons">
                        <?php foreach ($risk['reasons'] as $reason): ?><li class="<?= strpos($reason, 'registration period') !== false ? 'reason-warn' : '' ?>"><?= htmlspecialchars($reason) ?></li><?php endforeach; ?>
                    </ul>
                </div>
                <div class="rp-dd-block">
                    <h4>Detection</h4>
                    <dl>
                        <div><dt>Keyword</dt><dd><?= htmlspecialchars($sec['keyword']) ?></dd></div>
                        <div><dt>Source</dt><dd><?= ((string)($r['source'] ?? '') === 'ct') ? 'OpenINTEL' : 'CZDS' ?></dd></div>
                        <div><dt>Historical</dt><dd><?= !empty($r['is_historical']) ? 'Yes' : 'No' ?></dd></div>
                        <?php if ($er['ttdH'] !== null): ?><div><dt>Time-to-detect</dt><dd><?= (int)$er['ttdH'] ?> h from registration to first observation</dd></div><?php endif; ?>
                        <?php if (!empty($r['tag_note'])): ?><div><dt>Analyst note</dt><dd><?= htmlspecialchars((string)$r['tag_note']) ?></dd></div><?php endif; ?>
                    </dl>
                    <ul class="rp-reasons">
                        <?php foreach (reportFindings($r, $sec['keyword'], $er['age']) as $f): ?>
                            <li><b><?= htmlspecialchars($f['label']) ?></b><?= $f['value'] !== '' ? ': ' . htmlspecialchars((string)$f['value']) : '' ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>

            <h4>Timeline</h4>
            <ul class="rp-timeline">
                <?php foreach ($er['timeline'] as $ev): ?>
                    <li><span class="rp-tl-date"><?= htmlspecialchars(fmt_date((string)$ev['at'])) ?></span> &mdash; <?= htmlspecialchars($ev['label']) ?> <span class="rp-muted">(<?= htmlspecialchars($ev['source']) ?>)</span></li>
                <?php endforeach; ?>
            </ul>

            <?php if (($r['verdict'] ?? null) !== null): ?>
                <p class="rp-vt"><b>VirusTotal:</b> <a href="https://www.virustotal.com/gui/domain/<?= rawurlencode((string)($r['domain'] ?? '')) ?>">https://www.virustotal.com/gui/domain/<?= htmlspecialchars((string)($r['domain'] ?? '')) ?></a></p>
            <?php endif; ?>

            <?php if (!empty($showRaw)): ?>
                <h4>Raw data</h4>
                <pre class="rp-raw"><?= $rawJson ?></pre>
            <?php endif; ?>
        </div>
        <?php endforeach; endforeach; ?>
    </section>

    <div class="rp-foot">
        <?php if ($tlp !== ''): ?><b><?= htmlspecialchars($tlp) ?></b> &middot; <?php endif; ?>
        Generated by ThreatIntelligence-TDL on <?= htmlspecialchars($generatedAt) ?> &mdash;
        <?= number_format($totalDomains) ?> domain(s) across <?= count($sections) ?> keyword(s).
        Filters: <?= htmlspecialchars($filterSummary) ?>.
        Sources: WHOIS/RDAP + VirusTotal + AlienVault OTX (DNS, passive DNS, TLS and IP/ASN are not integrated).
    </div>
</div>

<script>
// Close the popup window after printing. Falls back to going back / Reports when
// the page was not opened by a script (where window.close() is ignored).
function closePrintWindow() {
    if (window.opener && !window.opener.closed) {
        window.close();
    } else if (window.history.length > 1) {
        window.history.back();
    } else {
        window.location.href = '/reports.php';
    }
}
</script>
