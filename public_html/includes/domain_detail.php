<?php
/**
 * Shared "rich" domain detail block.
 *
 * Builds the presentation data for a domain (WHOIS + VirusTotal + tag +
 * watchlist + match context) and renders the `.domain-detail` block used across
 * the app (Watchlist, Notifications and the Dashboard lookup): Assessment,
 * Timeline, Registration, Reputation, Detection and Raw data, plus the compact
 * `.dd-actions` footer.
 *
 * The action buttons call the shared handlers defined in assets/domain-detail.js
 * (`ddTag`, `ddWatchlist`, `ddFetchWhois`, `ddCheckVt`).
 */
require_once __DIR__ . '/report_present.php';

/**
 * Collect everything the detail block needs for one domain.
 *
 * @return array{present:array,keywords:array<int,string>}|null
 */
function domainDetailPresent(PDO $db, int $userId, string $domain): ?array {
    $domain = strtolower(trim($domain));
    if ($domain === '') {
        return null;
    }

    $newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));

    $wStmt = $db->prepare("SELECT domain, creation_date, creation_ts, expiration_date, registrar,
            name_servers, status, source, updated_at
        FROM domain_whois WHERE domain = ? LIMIT 1");
    $wStmt->execute([$domain]);
    $whoisRow = $wStmt->fetch() ?: null;

    $vStmt = $db->prepare("SELECT domain, verdict, malicious, suspicious, harmless, undetected,
            reputation, last_analysis_date, checked_at
        FROM domain_vt WHERE domain = ? LIMIT 1");
    $vStmt->execute([$domain]);
    $vtRow = $vStmt->fetch() ?: null;

    $aStmt = $db->prepare("SELECT domain, verdict, status, error, urlhaus_verdict, urlhaus_url_count, urlhaus_online,
            urlhaus_dbl, threatfox_verdict, threatfox_matches, threat_type, malware_family,
            confidence, tags, last_analysis_date, checked_at
        FROM domain_abusech WHERE domain = ? LIMIT 1");
    $aStmt->execute([$domain]);
    $abuseRow = $aStmt->fetch() ?: null;

    $cStmt = $db->prepare("SELECT domain, verdict, status, error, categories, phishing, radar_rank, technologies,
            asn, country, cert_issuer, report_url, dns_countries, last_analysis_date, checked_at
        FROM domain_cfscan WHERE domain = ? LIMIT 1");
    $cStmt->execute([$domain]);
    $cfRow = $cStmt->fetch() ?: null;

    $tStmt = $db->prepare("SELECT tag, note FROM domain_tags WHERE domain = ? LIMIT 1");
    $tStmt->execute([$domain]);
    $tagRow = $tStmt->fetch() ?: null;

    $wlStmt = $db->prepare("SELECT id FROM watchlist WHERE user_id = ? AND domain = ? LIMIT 1");
    $wlStmt->execute([$userId, $domain]);
    $inWatchlist = (bool)$wlStmt->fetchColumn();

    // All the keywords that matched this domain + the earliest match (used for
    // first_seen / discovered / source / historical).
    $mStmt = $db->prepare("SELECT m.first_seen, m.discovered_at, m.is_historical, m.source, k.keyword
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain = ?
        ORDER BY m.discovered_at ASC, m.domain ASC");
    $mStmt->execute([$userId, $domain]);
    $matches = $mStmt->fetchAll();
    $rep = $matches[0] ?? null;
    $keywords = [];
    foreach ($matches as $mrow) {
        if (!in_array($mrow['keyword'], $keywords, true)) {
            $keywords[] = $mrow['keyword'];
        }
    }

    $dot = strrpos($domain, '.');
    $tld = ($dot !== false) ? substr($domain, $dot + 1) : '';
    $creationDate = $whoisRow['creation_date'] ?? null;
    $isNew = false;
    if ($creationDate) {
        $ts = strtotime($creationDate);
        $isNew = $ts && $ts > strtotime("-{$newDomainDays} days");
    }
    $ns = (!empty($whoisRow['name_servers'])) ? (json_decode((string)$whoisRow['name_servers'], true) ?: []) : [];

    $present = [
        'domain'             => $domain,
        'tld'                => $tld,
        'discovered_at'      => $rep['discovered_at'] ?? null,
        'first_seen'         => $rep['first_seen'] ?? null,
        'is_historical'      => $rep['is_historical'] ?? 0,
        'source'             => $rep['source'] ?? null,
        'tag'                => (string)($tagRow['tag'] ?? ''),
        'tag_note'           => $tagRow['note'] ?? null,
        'in_watchlist'       => $inWatchlist ? 1 : 0,
        'creation_date'      => $creationDate,
        'expiration_date'    => $whoisRow['expiration_date'] ?? null,
        'registrar'          => $whoisRow['registrar'] ?? null,
        'name_servers'       => $whoisRow['name_servers'] ?? null,
        'whois_status'       => $whoisRow['status'] ?? null,
        'whois_source'       => $whoisRow['source'] ?? null,
        'whois_updated_at'   => $whoisRow['updated_at'] ?? null,
        'verdict'            => $vtRow['verdict'] ?? null,
        'malicious'          => $vtRow['malicious'] ?? null,
        'suspicious'         => $vtRow['suspicious'] ?? null,
        'harmless'           => $vtRow['harmless'] ?? null,
        'undetected'         => $vtRow['undetected'] ?? null,
        'reputation'         => $vtRow['reputation'] ?? null,
        'last_analysis_date' => $vtRow['last_analysis_date'] ?? null,
        'vt_checked_at'      => $vtRow['checked_at'] ?? null,
        'abusech_verdict'    => $abuseRow['verdict'] ?? null,
        'abusech_status'     => $abuseRow['status'] ?? null,
        'abusech_error'      => $abuseRow['error'] ?? null,
        'abusech_urlhaus_verdict' => $abuseRow['urlhaus_verdict'] ?? null,
        'abusech_urlhaus_url_count' => $abuseRow['urlhaus_url_count'] ?? null,
        'abusech_urlhaus_online' => $abuseRow['urlhaus_online'] ?? null,
        'abusech_urlhaus_dbl' => $abuseRow['urlhaus_dbl'] ?? null,
        'abusech_threatfox_verdict' => $abuseRow['threatfox_verdict'] ?? null,
        'abusech_threatfox_matches' => $abuseRow['threatfox_matches'] ?? null,
        'abusech_threat_type' => $abuseRow['threat_type'] ?? null,
        'abusech_malware_family' => $abuseRow['malware_family'] ?? null,
        'abusech_confidence' => $abuseRow['confidence'] ?? null,
        'abusech_tags'       => $abuseRow['tags'] ?? null,
        'abusech_last_analysis_date' => $abuseRow['last_analysis_date'] ?? null,
        'abusech_checked_at' => $abuseRow['checked_at'] ?? null,
        '_ns'                => $ns,
        '_is_new'            => $isNew,
    ] + cfscanPresentKeys($cfRow);

    return ['present' => $present, 'keywords' => $keywords];
}

/**
 * Render the `.domain-detail` block (grid + `.dd-actions` footer + raw data).
 *
 * @param array $present  Row built by domainDetailPresent() (or an equivalent).
 * @param array $keywords Keywords that matched the domain (may be empty).
 * @param array $rules    reportReviewRules() result.
 */
function renderDomainDetail(array $present, array $keywords, array $rules): string {
    $repSymbol = ['malicious' => '●', 'suspicious' => '⚠', 'dga' => '⚠', 'clean' => '✓', 'not_checked' => '○', 'unproven' => '○'];

    $domain = (string)($present['domain'] ?? '');
    $domainArg = htmlspecialchars(addslashes($domain));
    $ns = (array)($present['_ns'] ?? []);
    $keywordsLabel = implode(', ', array_filter(array_map('strval', $keywords), fn($k) => $k !== ''));

    $age = reportDomainAge($present['creation_date'] ?? null, gmdate('Y-m-d H:i:s'));
    $status = reportDomainStatus($present, $rules);
    $rep = reportReputationContextual(reportReputation($present), $age);
    $abuse = reportAbusech($present);
    $avail = reportAvailability($present);
    $whoisInfo = $avail['whois'];
    $risk = reportRiskAssessment($present, $status, $avail);
    $ttdH = reportTimeToDetectHours($present);
    $timeline = reportTimeline($present, '');
    $rawJson = htmlspecialchars(json_encode($present, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    $sourceLabel = (($present['source'] ?? '') === 'ct') ? 'OpenINTEL' : ((($present['source'] ?? '') !== '') ? 'CZDS' : '—');

    $tagVal = (string)($present['tag'] ?? '');
    $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];
    $hasTag = isset($tagLabels[$tagVal]);
    $tagCell = $hasTag
        ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
        : '<span class="muted">&mdash;</span>';

    // Cloudflare Radar verdict -> a reputation-like state.
    $cfState = 'not_checked';
    if (!empty($present['cf_status'])) {
        if ($present['cf_status'] === 'error') {
            $cfState = 'unproven';
        } elseif (($present['cf_verdict'] ?? '') === 'malicious') {
            $cfState = 'malicious';
        } elseif (($present['cf_verdict'] ?? '') === 'suspicious') {
            $cfState = 'suspicious';
        } elseif (($present['cf_verdict'] ?? '') === 'clean') {
            $cfState = 'clean';
        }
    }
    $cfLabels = ['malicious' => 'Malicious', 'suspicious' => 'Suspicious', 'clean' => 'Clean',
                 'not_checked' => 'Not checked', 'unproven' => 'Error'];
    $cfLabel = $cfLabels[$cfState] ?? 'Not checked';
    $cfDns = (array)($present['_cf_dns'] ?? []);
    $cfDetail = trim(implode(' · ', array_filter([
        (string)($present['cf_categories'] ?? ''),
        ($present['cf_phishing'] ?? '') !== '' ? 'phishing: ' . $present['cf_phishing'] : '',
    ])));

    ob_start();
    ?>
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
                    <li class="<?= strpos($reason, 'registration period') !== false ? 'reason-warn' : '' ?>"><?= htmlspecialchars($reason) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div class="dd-block">
            <h4>Timeline</h4>
            <ul class="report-timeline">
                <?php foreach ($timeline as $ev): ?>
                    <li><span class="tl-dot"></span><span class="tl-date"><?= htmlspecialchars(fmt_date((string)$ev['at'])) ?></span><span class="tl-label"><?= htmlspecialchars($ev['label']) ?></span><span class="tl-source muted"><?= htmlspecialchars($ev['source']) ?></span></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div class="dd-block">
            <h4>Registration</h4>
            <dl class="dd-list">
                <div><dt>Registrar</dt><dd><?= !empty($present['registrar']) ? htmlspecialchars((string)$present['registrar']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Name servers</dt><dd><?= !empty($ns) ? htmlspecialchars(implode(', ', $ns)) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>WHOIS</dt><dd><span class="avail avail-<?= htmlspecialchars($whoisInfo['state']) ?>"><?= htmlspecialchars($whoisInfo['label']) ?></span></dd></div>
                <div><dt>Source</dt><dd><?= !empty($present['whois_source']) ? htmlspecialchars((string)$present['whois_source']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Updated</dt><dd><?= !empty($present['whois_updated_at']) ? htmlspecialchars(fmt_date((string)$present['whois_updated_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
            </dl>
        </div>
        <div class="dd-block">
            <h4>Reputation</h4>
            <dl class="dd-list">
                <div><dt>VirusTotal</dt><dd><span class="rep-pill rep-<?= htmlspecialchars($rep['state']) ?>"><?= htmlspecialchars($repSymbol[$rep['state']] ?? '') ?> <?= htmlspecialchars($rep['label']) ?></span><?php if ($rep['detail'] !== ''): ?> <span class="muted"><?= htmlspecialchars($rep['detail']) ?></span><?php endif; ?></dd></div>
                <div><dt>Abuse.ch</dt><dd><span class="rep-pill rep-<?= htmlspecialchars($abuse['state']) ?>"><?= htmlspecialchars($repSymbol[$abuse['state']] ?? '') ?> <?= htmlspecialchars($abuse['label']) ?></span><?php if ($abuse['detail'] !== ''): ?> <span class="muted"><?= htmlspecialchars($abuse['detail']) ?></span><?php endif; ?></dd></div>
                <div><dt>Last analysis</dt><dd><?= htmlspecialchars(reportFormatDate($present['last_analysis_date'] ?? null)) ?></dd></div>
                <div><dt>Checked</dt><dd><?= !empty($present['vt_checked_at']) ? htmlspecialchars(fmt_date((string)$present['vt_checked_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Tag</dt><dd><?= $tagCell ?></dd></div>
                <div><dt>Watchlist</dt><dd><?= !empty($present['in_watchlist']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
            </dl>
        </div>
        <div class="dd-block">
            <h4>Cloudflare Radar</h4>
            <dl class="dd-list">
                <div><dt>Verdict</dt><dd><span class="rep-pill rep-<?= htmlspecialchars($cfState) ?>"><?= htmlspecialchars($repSymbol[$cfState] ?? '') ?> <?= htmlspecialchars($cfLabel) ?></span><?php if ($cfState === 'unproven' && !empty($present['cf_error'])): ?> <span class="muted"><?= htmlspecialchars((string)$present['cf_error']) ?></span><?php elseif ($cfDetail !== ''): ?> <span class="muted"><?= htmlspecialchars($cfDetail) ?></span><?php endif; ?></dd></div>
                <div><dt>Radar rank</dt><dd><?= !empty($present['cf_radar_rank']) ? htmlspecialchars((string)$present['cf_radar_rank']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Technologies</dt><dd><?= !empty($present['cf_technologies']) ? htmlspecialchars((string)$present['cf_technologies']) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Hosting</dt><dd><?php
                    $hostBits = array_filter([(string)($present['cf_asn'] ?? ''), (string)($present['cf_country'] ?? '')]);
                    echo $hostBits ? htmlspecialchars(implode(' · ', $hostBits)) : '<span class="muted">&mdash;</span>';
                ?></dd></div>
                <div><dt>Checked</dt><dd><?= !empty($present['cf_checked_at']) ? htmlspecialchars(fmt_date((string)$present['cf_checked_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
            </dl>
            <?php if (!empty($cfDns)): ?>
            <div><span class="muted">DNS queries by country (7d)</span>
                <ul class="dd-findings">
                    <?php foreach ($cfDns as $loc):
                        if (!is_array($loc)) continue;
                        $locName = (string)($loc['name'] ?? $loc['code'] ?? '');
                        $locVal = is_numeric($loc['value'] ?? null) ? round((float)$loc['value'], 1) : (string)($loc['value'] ?? '');
                    ?>
                    <li><strong><?= htmlspecialchars($locName) ?></strong> <span class="muted"><?= htmlspecialchars((string)$locVal) ?>%</span></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
        </div>
        <div class="dd-block">
            <h4>Detection</h4>
            <dl class="dd-list">
                <div><dt>Keywords</dt><dd><?= $keywordsLabel !== '' ? htmlspecialchars($keywordsLabel) : '<span class="muted">&mdash;</span>' ?></dd></div>
                <div><dt>Source</dt><dd><?= htmlspecialchars($sourceLabel) ?></dd></div>
                <div><dt>Historical</dt><dd><?= !empty($present['is_historical']) ? 'Yes' : '<span class="muted">No</span>' ?></dd></div>
                <?php if ($ttdH !== null): ?>
                    <div><dt>Time-to-detect</dt><dd><?= (int)$ttdH ?> h from registration to first observation</dd></div>
                <?php endif; ?>
                <?php if (!empty($present['tag_note'])): ?>
                    <div><dt>Analyst note</dt><dd><?= htmlspecialchars((string)$present['tag_note']) ?></dd></div>
                <?php endif; ?>
            </dl>
            <ul class="dd-findings">
                <?php foreach (reportFindings($present, $keywordsLabel, $age) as $f): ?>
                    <li class="finding-<?= htmlspecialchars($f['severity']) ?>"><strong><?= htmlspecialchars($f['label']) ?></strong><?= $f['value'] !== '' ? ': <span class="muted">' . htmlspecialchars((string)$f['value']) . '</span>' : '' ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <div class="dd-actions">
        <button type="button" class="btn btn-small btn-good waves-effect" onclick="ddTag('<?= $domainArg ?>', 'good')">Mark Good</button>
        <button type="button" class="btn btn-small btn-bad waves-effect" onclick="ddTag('<?= $domainArg ?>', 'bad')">Mark Bad</button>
        <button type="button" class="btn btn-small btn-warning waves-effect" onclick="ddTag('<?= $domainArg ?>', 'observing')"><i class="material-icons left">help_outline</i>Insufficient info</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="ddTag('<?= $domainArg ?>', '')">Clear</button>
        <button type="button" class="btn btn-small btn-outline waves-effect" onclick="ddWatchlist('<?= $domainArg ?>')"><i class="material-icons left">star</i><?= !empty($present['in_watchlist']) ? 'Remove from Watchlist' : 'Add to Watchlist' ?></button>
        <button type="button" class="btn btn-small waves-effect" onclick="ddFetchWhois('<?= $domainArg ?>')"><i class="material-icons left">cloud_download</i>Fetch WHOIS (worker)</button>
        <button type="button" class="btn btn-small waves-effect" onclick="ddCheckVt('<?= $domainArg ?>')"><i class="material-icons left">verified_user</i>Check VirusTotal</button>
        <button type="button" class="btn btn-small waves-effect" onclick="ddCheckAbusech('<?= $domainArg ?>')"><i class="material-icons left">gpp_maybe</i>Check Abuse.ch</button>
        <button type="button" class="btn btn-small waves-effect" onclick="ddCheckCf('<?= $domainArg ?>')"><i class="material-icons left">cloud</i>Scan with Cloudflare</button>
        <button type="button" class="btn btn-small waves-effect" onclick="ddCheckCfdns('<?= $domainArg ?>')"><i class="material-icons left">public</i>Cloudflare DNS</button>
        <a class="btn btn-small btn-info waves-effect" href="https://www.virustotal.com/gui/domain/<?= rawurlencode($domain) ?>" target="_blank" rel="noopener"><i class="material-icons left">shield</i>Open in VirusTotal</a>
        <a class="btn btn-small btn-info waves-effect" href="https://urlhaus.abuse.ch/host/<?= rawurlencode($domain) ?>/" target="_blank" rel="noopener"><i class="material-icons left">bug_report</i>Open in URLhaus</a>
        <?php if (!empty($present['cf_report_url'])): ?>
        <a class="btn btn-small btn-info waves-effect" href="<?= htmlspecialchars((string)$present['cf_report_url']) ?>" target="_blank" rel="noopener"><i class="material-icons left">radar</i>Open in URL Scanner</a>
        <?php endif; ?>
        <?php if (!empty($_SESSION['is_admin'])): ?>
        <button type="button" class="btn btn-small btn-danger waves-effect" onclick="ddDeleteFicha('<?= $domainArg ?>')" title="Delete the cached WHOIS/VirusTotal/abuse.ch/Cloudflare data for this domain. Tags, watchlist, reports and Intelligence are kept."><i class="material-icons left">delete_sweep</i>Delete cache</button>
        <?php endif; ?>
    </div>
    <details class="dd-raw">
        <summary>Raw data</summary>
        <pre><?= $rawJson ?></pre>
    </details>
</div>
    <?php
    return (string)ob_get_clean();
}
