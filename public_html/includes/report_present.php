<?php
/**
 * Report presentation helpers.
 *
 * Pure functions that derive the "threat intelligence" view fields (age,
 * assessment status, detection reasons, reputation state, data availability)
 * from the fields already stored in a report snapshot. Nothing here touches the
 * database schema or the data collection: it is a transformation layer over what
 * the system already knows, so old saved reports render with the new layout too.
 *
 * Guiding rule (from the ideas doc): never present absence of evidence as
 * evidence of absence, and keep "not checked" different from "benign".
 */

/** Tunable "review required" rules (settings; both default to enabled). */
function reportReviewRules(PDO $db): array {
    return [
        'new'     => getSetting($db, 'report_review_on_new', '1') !== '0',
        'keyword' => getSetting($db, 'report_review_on_keyword', '1') !== '0',
    ];
}

/** Age in days between a UTC creation date and a reference UTC instant. */
function reportDomainAge(?string $createdUtc, ?string $refUtc): ?int {
    if (!$createdUtc) {
        return null;
    }
    $created = strtotime($createdUtc);
    $ref = $refUtc ? strtotime($refUtc) : time();
    if ($created === false || $ref === false || $created > $ref) {
        return null;
    }
    return (int)floor(($ref - $created) / 86400);
}

/** Human label for a day count. */
function reportAgeLabel(?int $days): string {
    if ($days === null) {
        return 'unknown';
    }
    if ($days === 0) {
        return 'today';
    }
    return $days . ($days === 1 ? ' day' : ' days');
}

/**
 * Assessment status, mutually exclusive by priority:
 * malicious > suspicious > benign > review_required > unknown.
 */
function reportDomainStatus(array $row, array $rules): string {
    $verdict = (string)($row['verdict'] ?? '');
    $tag = (string)($row['tag'] ?? '');
    $abuseVerdict = (string)($row['abusech_verdict'] ?? '');

    if ($tag === 'bad' || $verdict === 'malicious' || $abuseVerdict === 'malicious') {
        return 'malicious';
    }
    if ($verdict === 'suspicious' || $verdict === 'dga' || $abuseVerdict === 'suspicious') {
        return 'suspicious';
    }
    if ($tag === 'good') {
        return 'benign';
    }
    if ($tag === 'observing') {
        return 'review_required';
    }
    if (($rules['new'] && !empty($row['_is_new'])) || $rules['keyword']) {
        return 'review_required';
    }
    return 'unknown';
}

/** Human label for a status code. */
function reportStatusLabel(string $status): string {
    $labels = [
        'malicious'       => 'Malicious',
        'suspicious'      => 'Suspicious',
        'benign'          => 'Benign',
        'review_required' => 'Review required',
        'unknown'         => 'Unknown',
    ];
    return $labels[$status] ?? ucfirst($status);
}

/** Short "why flagged" text for the triage table. */
function reportWhyFlagged(array $row): string {
    $bits = ['Keyword'];
    if (!empty($row['_is_new'])) {
        $bits[] = 'New';
    }
    $tag = (string)($row['tag'] ?? '');
    if ($tag === 'bad') {
        $bits[] = 'Bad';
    } elseif ($tag === 'good') {
        $bits[] = 'Good';
    } elseif ($tag === 'observing') {
        $bits[] = 'Observing';
    }
    if (!empty($row['in_watchlist'])) {
        $bits[] = 'Watchlist';
    }
    return implode(' + ', $bits);
}

/** Structured detection reasons (for the domain detail panel). */
function reportFindings(array $row, string $keyword, ?int $ageDays): array {
    $out = [];
    $out[] = ['type' => 'keyword_match', 'label' => 'Keyword match', 'value' => $keyword, 'severity' => 'info'];
    if (!empty($row['_is_new'])) {
        $out[] = ['type' => 'recent_registration', 'label' => 'Recently registered',
                  'value' => reportAgeLabel($ageDays), 'severity' => 'warning'];
    }
    if (!empty($row['first_seen'])) {
        $out[] = ['type' => 'first_seen', 'label' => 'First observed',
                  'value' => fmt_date((string)$row['first_seen']), 'severity' => 'info'];
    }
    $tag = (string)($row['tag'] ?? '');
    if (in_array($tag, ['good', 'bad', 'observing'], true)) {
        $out[] = ['type' => 'analyst_tag', 'label' => 'Analyst classification',
                  'value' => strtoupper($tag), 'severity' => 'info'];
    }
    if (!empty($row['in_watchlist'])) {
        $out[] = ['type' => 'watchlist', 'label' => 'In watchlist', 'value' => '', 'severity' => 'info'];
    }
    $abuse = reportAbusech($row);
    if (in_array($abuse['state'], ['malicious', 'suspicious'], true)) {
        $out[] = ['type' => 'abusech', 'label' => 'Abuse.ch',
                  'value' => $abuse['label'] . ($abuse['detail'] !== '' ? ' (' . $abuse['detail'] . ')' : ''),
                  'severity' => 'warning'];
    }
    return $out;
}

/** Reputation state from the cached VirusTotal data (never "benign" here). */
function reportReputation(array $row): array {
    if (($row['verdict'] ?? null) === null) {
        return ['state' => 'not_checked', 'label' => 'Not checked', 'detail' => ''];
    }
    $verdict = (string)$row['verdict'];
    $total = (int)($row['malicious'] ?? 0) + (int)($row['suspicious'] ?? 0)
        + (int)($row['harmless'] ?? 0) + (int)($row['undetected'] ?? 0);
    $hits = (int)($row['malicious'] ?? 0) + (int)($row['suspicious'] ?? 0);

    if ($verdict === 'clean') {
        return ['state' => 'clean', 'label' => 'No detections',
                'detail' => $total > 0 ? ('0 of ' . $total . ' engines') : ''];
    }
    $labels = ['malicious' => 'Malicious', 'suspicious' => 'Suspicious', 'dga' => 'DGA'];
    return [
        'state'  => $verdict,
        'label'  => $labels[$verdict] ?? ucfirst($verdict),
        'detail' => $total > 0 ? ($hits . ' of ' . $total . ' engines') : '',
    ];
}

/**
 * abuse.ch validation from the cached URLhaus + ThreatFox data.
 *
 * URLhaus confirms the host is used for malware distribution (Spamhaus DBL
 * phishing/botnet/abused classifications and currently-serving payloads are
 * malicious; offline/other listings are suspicious). ThreatFox only accepts
 * confirmed IOCs, so any match is malicious.
 */
function reportAbusech(array $row): array {
    $status = strtolower((string)($row['abusech_status'] ?? ''));
    $error  = trim((string)($row['abusech_error'] ?? ''));
    if ($status === 'error' || $error !== '') {
        return ['state' => 'error', 'label' => 'Error', 'detail' => $error !== '' ? $error : 'query failed'];
    }
    if (($row['abusech_verdict'] ?? null) === null || (string)$row['abusech_verdict'] === '') {
        return ['state' => 'not_checked', 'label' => 'Not checked', 'detail' => ''];
    }
    $verdict = (string)$row['abusech_verdict'];

    $bits = [];
    $urlhausV = (string)($row['abusech_urlhaus_verdict'] ?? '');
    $urlCount = (int)($row['abusech_urlhaus_url_count'] ?? 0);
    if ($urlhausV === 'malicious') {
        $bits[] = 'URLhaus: ' . $urlCount . ' malware URL' . ($urlCount === 1 ? '' : 's');
    } elseif ($urlhausV === 'suspicious') {
        $dbl = trim((string)($row['abusech_urlhaus_dbl'] ?? ''));
        $bits[] = 'URLhaus' . ($dbl !== '' && $dbl !== 'not listed' ? ': ' . $dbl : ($urlCount > 0 ? ': ' . $urlCount . ' URL(s)' : ''));
    }
    $tfV = (string)($row['abusech_threatfox_verdict'] ?? '');
    if ($tfV === 'malicious') {
        $fam = trim((string)($row['abusech_malware_family'] ?? ''));
        $tt = trim((string)($row['abusech_threat_type'] ?? ''));
        $bits[] = 'ThreatFox' . ($fam !== '' ? ': ' . $fam : ($tt !== '' ? ': ' . $tt : ''));
    }
    $detail = implode(' · ', array_filter($bits));

    $labels = ['malicious' => 'Malicious', 'suspicious' => 'Suspicious', 'clean' => 'Not found'];
    return [
        'state'  => ($verdict === 'clean') ? 'clean' : $verdict,
        'label'  => $labels[$verdict] ?? ucfirst($verdict),
        'detail' => $detail,
    ];
}

/**
 * Map a `domain_abusech` row to the abusech_* keys used by the presentation
 * helpers (reportAbusech / renderDomainDetail). Missing rows yield nulls, which
 * reportAbusech renders as "Not checked".
 */
function abusechPresentKeys(?array $row): array {
    return [
        'abusech_verdict'            => $row['verdict'] ?? null,
        'abusech_status'             => $row['status'] ?? null,
        'abusech_error'              => $row['error'] ?? null,
        'abusech_urlhaus_verdict'    => $row['urlhaus_verdict'] ?? null,
        'abusech_urlhaus_url_count'  => $row['urlhaus_url_count'] ?? null,
        'abusech_urlhaus_online'     => $row['urlhaus_online'] ?? null,
        'abusech_urlhaus_dbl'        => $row['urlhaus_dbl'] ?? null,
        'abusech_threatfox_verdict'  => $row['threatfox_verdict'] ?? null,
        'abusech_threatfox_matches'  => $row['threatfox_matches'] ?? null,
        'abusech_threat_type'        => $row['threat_type'] ?? null,
        'abusech_malware_family'     => $row['malware_family'] ?? null,
        'abusech_confidence'         => $row['confidence'] ?? null,
        'abusech_tags'               => $row['tags'] ?? null,
        'abusech_last_analysis_date' => $row['last_analysis_date'] ?? null,
        'abusech_checked_at'         => $row['checked_at'] ?? null,
    ];
}

/** Compact badge cell for the abuse.ch column of the match/notification lists. */
function abusechBadge(?array $row): string {
    if (!$row) {
        return '<span class="muted">&mdash;</span>';
    }
    if (strtolower((string)($row['status'] ?? '')) === 'error') {
        $err = trim((string)($row['error'] ?? ''));
        return '<span class="vt-badge vt-error" title="' . htmlspecialchars($err !== '' ? $err : 'abuse.ch query failed') . '">AC ERROR</span>';
    }
    $v = (string)($row['verdict'] ?? '');
    $labels = ['malicious' => 'MALICIOUS', 'suspicious' => 'SUSPICIOUS', 'clean' => 'NOT FOUND'];
    if (!isset($labels[$v])) {
        return '<span class="muted">&mdash;</span>';
    }
    $title = [];
    if ((string)($row['urlhaus_verdict'] ?? '') === 'malicious') {
        $title[] = 'URLhaus: ' . (int)($row['urlhaus_url_count'] ?? 0) . ' malware URL(s)';
    } elseif ((string)($row['urlhaus_verdict'] ?? '') === 'suspicious') {
        $title[] = 'URLhaus: ' . ((string)($row['urlhaus_dbl'] ?? '') !== '' ? $row['urlhaus_dbl'] : 'listed');
    }
    if ((string)($row['threatfox_verdict'] ?? '') === 'malicious') {
        $fam = trim((string)($row['malware_family'] ?? ''));
        $title[] = 'ThreatFox: ' . ($fam !== '' ? $fam : 'confirmed IOC');
    }
    return '<span class="vt-badge vt-' . htmlspecialchars($v) . '" title="' . htmlspecialchars(implode(' · ', $title)) . '">AC ' . $labels[$v] . '</span>';
}

/**
 * Map a `domain_cfscan` row to the cf_* keys used by the presentation helpers
 * (renderDomainDetail). Missing rows yield nulls, rendered as "Not checked".
 */
function cfscanPresentKeys(?array $row): array {
    $dns = [];
    if ($row && !empty($row['dns_countries'])) {
        $decoded = json_decode((string)$row['dns_countries'], true);
        if (is_array($decoded)) {
            $dns = $decoded;
        }
    }
    return [
        'cf_verdict'      => $row['verdict'] ?? null,
        'cf_status'       => $row['status'] ?? null,
        'cf_error'        => $row['error'] ?? null,
        'cf_categories'   => $row['categories'] ?? null,
        'cf_phishing'     => $row['phishing'] ?? null,
        'cf_radar_rank'   => $row['radar_rank'] ?? null,
        'cf_technologies' => $row['technologies'] ?? null,
        'cf_asn'          => $row['asn'] ?? null,
        'cf_country'      => $row['country'] ?? null,
        'cf_cert_issuer'  => $row['cert_issuer'] ?? null,
        'cf_report_url'   => $row['report_url'] ?? null,
        'cf_checked_at'   => $row['checked_at'] ?? null,
        '_cf_dns'         => $dns,
    ];
}

/** Compact badge cell for the Cloudflare Radar column of the lists. */
function cfscanBadge(?array $row): string {
    if (!$row) {
        return '<span class="muted">&mdash;</span>';
    }
    if (strtolower((string)($row['status'] ?? '')) === 'error') {
        $err = trim((string)($row['error'] ?? ''));
        return '<span class="vt-badge vt-error" title="' . htmlspecialchars($err !== '' ? $err : 'Cloudflare scan failed') . '">CF ERROR</span>';
    }
    $v = (string)($row['verdict'] ?? '');
    $labels = ['malicious' => 'MALICIOUS', 'suspicious' => 'SUSPICIOUS', 'clean' => 'CLEAN'];
    if (!isset($labels[$v])) {
        return '<span class="muted">&mdash;</span>';
    }
    $title = [];
    if (!empty($row['categories'])) {
        $title[] = 'Categories: ' . $row['categories'];
    }
    if (!empty($row['radar_rank'])) {
        $title[] = 'Radar rank: ' . $row['radar_rank'];
    }
    if (!empty($row['technologies'])) {
        $title[] = 'Technologies: ' . $row['technologies'];
    }
    return '<span class="vt-badge vt-' . htmlspecialchars($v) . '" title="' . htmlspecialchars(implode(' · ', $title)) . '">CF ' . $labels[$v] . '</span>';
}

/**
 * Data availability per source (WHOIS + VirusTotal + abuse.ch).
 */
function reportAvailability(array $row): array {
    $ws = (string)($row['whois_status'] ?? '');
    if ($ws === '') {
        $whois = ['state' => 'not_checked', 'label' => 'Not checked'];
    } elseif ($ws === 'ok') {
        $whois = ['state' => 'ok', 'label' => 'Available'];
    } elseif ($ws === 'unsupported') {
        $whois = ['state' => 'unsupported', 'label' => 'Not published'];
    } else {
        $whois = ['state' => 'error', 'label' => 'Error'];
    }
    $vt = ($row['verdict'] ?? null) === null
        ? ['state' => 'not_checked', 'label' => 'Not checked']
        : ['state' => 'ok', 'label' => 'Checked'];
    $abusechStatus = strtolower((string)($row['abusech_status'] ?? ''));
    if ($abusechStatus === 'error') {
        $abusech = ['state' => 'error', 'label' => 'Error'];
    } elseif (($row['abusech_verdict'] ?? null) === null || (string)$row['abusech_verdict'] === '') {
        $abusech = ['state' => 'not_checked', 'label' => 'Not checked'];
    } else {
        $abusech = ['state' => 'ok', 'label' => 'Checked'];
    }
    return ['whois' => $whois, 'vt' => $vt, 'abusech' => $abusech];
}

/**
 * Basic timeline (created / first seen / discovered / report generated).
 * Returns events sorted by timestamp; unknown dates are simply omitted.
 */
function reportTimeline(array $row, string $generatedAtUtc): array {
    $events = [];
    if (!empty($row['creation_date'])) {
        $events[] = ['at' => (string)$row['creation_date'], 'label' => 'Domain created', 'source' => 'WHOIS'];
    }
    if (!empty($row['first_seen'])) {
        $events[] = ['at' => (string)$row['first_seen'], 'label' => 'First seen in zone', 'source' => 'CZDS/OpenINTEL'];
    }
    if (!empty($row['discovered_at'])) {
        $events[] = ['at' => (string)$row['discovered_at'], 'label' => 'Matching domain observed', 'source' => 'Worker'];
    }
    if ($generatedAtUtc !== '') {
        $events[] = ['at' => $generatedAtUtc, 'label' => 'Report generated', 'source' => 'Application'];
    }
    usort($events, function ($a, $b) {
        return (strtotime($a['at']) ?: 0) <=> (strtotime($b['at']) ?: 0);
    });
    return $events;
}

/**
 * Explainable risk + confidence. Risk is the intensity of the collected
 * signals; confidence is the quality/quantity of the evidence (data
 * availability). No opaque numeric score.
 */
function reportRiskAssessment(array $row, string $status, array $avail): array {
    $reasons = [];
    if ($status === 'malicious') {
        $risk = 'high';
        $reasons[] = 'Confirmed malicious verdict or analyst classification';
    } elseif ($status === 'suspicious') {
        $risk = 'high';
        $reasons[] = 'Suspicious reputation verdict';
    } elseif ($status === 'review_required') {
        $risk = !empty($row['_is_new']) ? 'medium' : 'low';
        if (!empty($row['_is_new'])) {
            $reasons[] = 'Recently registered';
        }
        $reasons[] = 'Keyword match';
        if (!empty($row['in_watchlist'])) {
            $reasons[] = 'In watchlist';
        }
    } elseif ($status === 'benign') {
        $risk = 'low';
        $reasons[] = 'Classified good by an analyst';
    } else {
        $risk = 'low';
        $reasons[] = 'No strong signal';
    }

    // A minimum registration period (~1 year) is a disposable-infrastructure
    // signal: raise the risk one step and state it explicitly.
    $regSpan = reportRegistrationSpanReason($row);
    if ($regSpan !== null) {
        $reasons[] = $regSpan;
        if ($risk === 'low') {
            $risk = 'medium';
        } elseif ($risk === 'medium') {
            $risk = 'high';
        }
    }

    // abuse.ch: URLhaus malware host / ThreatFox confirmed IOC.
    $abuse = reportAbusech($row);
    if (in_array($abuse['state'], ['malicious', 'suspicious'], true)) {
        $reasons[] = 'Abuse.ch: ' . ($abuse['detail'] !== '' ? $abuse['detail'] : $abuse['label']);
    }

    $whoisOk = (($avail['whois']['state'] ?? '') === 'ok');
    $vtChecked = (($avail['vt']['state'] ?? '') === 'ok');
    $abuseChecked = (($avail['abusech']['state'] ?? '') === 'ok');
    if ($whoisOk && $vtChecked && $abuseChecked) {
        $confidence = 'high';
    } elseif ($whoisOk || $vtChecked || $abuseChecked) {
        $confidence = 'medium';
    } else {
        $confidence = 'low';
    }
    if (!$whoisOk) {
        $reasons[] = 'WHOIS data not available';
    }
    if (!$vtChecked) {
        $reasons[] = 'Reputation not checked';
    }
    if (!$abuseChecked) {
        $reasons[] = 'Abuse.ch not checked';
    }
    return ['risk' => $risk, 'confidence' => $confidence, 'reasons' => $reasons];
}

/**
 * Shared infrastructure inside the report: name servers / registrars used by
 * more than one domain. Pure correlation of the collected data.
 *
 * @param array $sections Report sections (each with enriched 'rows').
 * @return array{nameservers:array<string,string[]>,registrars:array<string,string[]>}
 */
function reportSharedInfrastructure(array $sections): array {
    $nsMap = [];
    $regMap = [];
    foreach ($sections as $sec) {
        foreach ($sec['rows'] as $er) {
            $r = $er['row'];
            $domain = (string)($r['domain'] ?? '');
            if ($domain === '') {
                continue;
            }
            foreach ((array)($r['_ns'] ?? []) as $ns) {
                $ns = strtolower(trim((string)$ns));
                if ($ns !== '') {
                    $nsMap[$ns][$domain] = true;
                }
            }
            $reg = trim((string)($r['registrar'] ?? ''));
            if ($reg !== '') {
                $regMap[$reg][$domain] = true;
            }
        }
    }
    $shared = ['nameservers' => [], 'registrars' => []];
    foreach ($nsMap as $ns => $doms) {
        if (count($doms) > 1) {
            $shared['nameservers'][$ns] = array_keys($doms);
        }
    }
    foreach ($regMap as $reg => $doms) {
        if (count($doms) > 1) {
            $shared['registrars'][$reg] = array_keys($doms);
        }
    }
    uasort($shared['nameservers'], fn($a, $b) => count($b) <=> count($a));
    uasort($shared['registrars'], fn($a, $b) => count($b) <=> count($a));
    return $shared;
}

/**
 * Aggregate a report (saved snapshot's `report` array) into the counters used
 * for the Executive Summary and the previous-report comparison.
 */
function reportAggregateReport(array $report, array $rules, string $refUtc): array {
    $agg = [
        'domains' => 0, 'new' => 0, 'watchlist' => 0, 'not_checked_vt' => 0,
        'status' => ['malicious' => 0, 'suspicious' => 0, 'benign' => 0, 'review_required' => 0, 'unknown' => 0],
    ];
    foreach ($report as $data) {
        $rows = is_array($data['rows'] ?? null) ? $data['rows'] : [];
        foreach ($rows as $r) {
            $status = reportDomainStatus($r, $rules);
            $rep = reportReputation($r);
            $agg['domains']++;
            if (!empty($r['_is_new'])) { $agg['new']++; }
            if (!empty($r['in_watchlist'])) { $agg['watchlist']++; }
            if ($rep['state'] === 'not_checked') { $agg['not_checked_vt']++; }
            $agg['status'][$status]++;
        }
    }
    return $agg;
}

/**
 * Format a stored date value for display. Handles Unix timestamps (e.g. the
 * VirusTotal `last_analysis_date`) as well as ISO/SQLite date strings; returns
 * an em dash when there is nothing to show.
 */
function reportFormatDate($value): string {
    if ($value === null || $value === '') {
        return '—';
    }
    $v = (string)$value;
    if (ctype_digit($v)) {
        $ts = (int)$v;
        return $ts > 0 ? date('Y-m-d', $ts) : '—';
    }
    return fmt_date($v);
}

/* ==========================================================================
   Visual risk-signal helpers (report hierarchy)
   ========================================================================== */

/** TLDs statistically over-represented in abuse (editable heuristic). */
function reportRiskTlds(): array {
    return [
        'xyz', 'top', 'icu', 'click', 'link', 'live', 'rest', 'cfd', 'sbs', 'shop',
        'quest', 'buzz', 'monster', 'lol', 'cam', 'cyou', 'fit', 'autos', 'boats', 'beauty',
    ];
}

/** Age tier: the product's #1 signal. Unknown age is neutral, never "fresh". */
function reportAgeTier(?int $days): string {
    if ($days === null) {
        return 'unknown';
    }
    if ($days <= 7) {
        return 'fresh';
    }
    if ($days <= 30) {
        return 'young';
    }
    if ($days <= 90) {
        return 'recent';
    }
    return 'established';
}

/** CSS class for the age tier (e.g. age-fresh). */
function reportAgeClass(?int $days): string {
    return 'age-' . reportAgeTier($days);
}

/** Domain with the matched keyword highlighted (HTML-safe, multibyte-safe). */
function reportHighlightKeyword(string $domain, string $keyword): string {
    if ($keyword === '' || strpbrk($keyword, '*?[]{}') !== false) {
        // Glob patterns have no single literal span to highlight.
        return htmlspecialchars($domain);
    }
    if (function_exists('mb_stripos')) {
        $pos = mb_stripos($domain, $keyword, 0, 'UTF-8');
        if ($pos === false) {
            return htmlspecialchars($domain);
        }
        $len = mb_strlen($keyword, 'UTF-8');
        return htmlspecialchars(mb_substr($domain, 0, $pos, 'UTF-8'))
            . '<mark class="kw-hit">' . htmlspecialchars(mb_substr($domain, $pos, $len, 'UTF-8')) . '</mark>'
            . htmlspecialchars(mb_substr($domain, $pos + $len, null, 'UTF-8'));
    }
    // Fallback when mbstring is not available (byte-based; fine for ASCII/IDN-punycode).
    $pos = stripos($domain, $keyword);
    if ($pos === false) {
        return htmlspecialchars($domain);
    }
    $len = strlen($keyword);
    return htmlspecialchars(substr($domain, 0, $pos))
        . '<mark class="kw-hit">' . htmlspecialchars(substr($domain, $pos, $len)) . '</mark>'
        . htmlspecialchars(substr($domain, $pos + $len));
}

/** Risk-TLD badge for a domain ('' when not applicable). */
function reportTldBadge(string $domain): string {
    $dot = strrpos($domain, '.');
    if ($dot === false) {
        return '';
    }
    $tld = strtolower(substr($domain, $dot + 1));
    if (in_array($tld, reportRiskTlds(), true)) {
        return '<span class="tld-risk" title="TLD with a high abuse rate">.' . htmlspecialchars($tld) . '</span>';
    }
    return '';
}

/**
 * Contextual reputation: "0 detections" on a young (or unknown-age) domain is
 * not proof of benign -> grey "unproven" instead of green "clean".
 */
function reportReputationContextual(array $rep, ?int $ageDays): array {
    if (($rep['state'] ?? '') === 'clean' && ($ageDays === null || $ageDays <= 30)) {
        $detail = (string)($rep['detail'] ?? '');
        $extra = 'insufficient history (' . reportAgeLabel($ageDays) . ')';
        return [
            'state'  => 'unproven',
            'label'  => $rep['label'],
            'detail' => $detail !== '' ? $detail . ' · ' . $extra : $extra,
        ];
    }
    return $rep;
}

/** Row severity for the lateral triage strip (neutral when age is unknown). */
function reportRowSeverity(string $status, ?int $ageDays): string {
    if ($status === 'malicious') {
        return 'sev-critical';
    }
    if ($status === 'suspicious') {
        return 'sev-high';
    }
    if ($ageDays !== null && $ageDays <= 7) {
        return 'sev-elevated';
    }
    if ($status === 'review_required') {
        return 'sev-medium';
    }
    return 'sev-none';
}

/** WHOIS class: only a registered domain is positive; "available" is neutral. */
function reportWhoisClass(string $label): string {
    return in_array(strtolower(trim($label)), ['registered', 'ok'], true) ? 'whois-registered' : 'whois-neutral';
}

/**
 * Parse a stored date for DateTimeImmutable. Unix timestamps and naive strings
 * are treated as UTC so time-to-detect does not shift with the server timezone.
 */
function reportParseDateArg($value): string {
    $v = trim((string)$value);
    if ($v === '') {
        return $v;
    }
    if (ctype_digit($v)) {
        return '@' . $v;
    }
    if (!preg_match('/(?:Z|[+\-]\d{2}:?\d{2})$/', $v)) {
        $v .= ' UTC';
    }
    return $v;
}

/** Minimum registration period (~1 year) => disposable-infrastructure signal. */
function reportRegistrationSpanReason(array $row): ?string {
    if (empty($row['creation_date']) || empty($row['expiration_date'])) {
        return null;
    }
    try {
        $c = new DateTimeImmutable(reportParseDateArg($row['creation_date']));
        $e = new DateTimeImmutable(reportParseDateArg($row['expiration_date']));
    } catch (Exception $ex) {
        return null;
    }
    $days = (int)round(($e->getTimestamp() - $c->getTimestamp()) / 86400);
    if ($days > 0 && $days <= 370) {
        return sprintf('Minimum registration period (%d days): common pattern of disposable infrastructure', $days);
    }
    return null;
}

/** Hours between registration and first observation in the zone. */
function reportTimeToDetectHours(array $row): ?int {
    if (empty($row['creation_date']) || empty($row['first_seen'])) {
        return null;
    }
    try {
        $c = new DateTimeImmutable(reportParseDateArg($row['creation_date']));
        $s = new DateTimeImmutable(reportParseDateArg($row['first_seen']));
    } catch (Exception $ex) {
        return null;
    }
    $h = (int)round(($s->getTimestamp() - $c->getTimestamp()) / 3600);
    return $h >= 0 ? $h : null;
}

/** Delta chip vs the previous report ('' when unchanged). */
function reportDeltaChip(int $prev, int $curr, string $label): string {
    if ($prev === $curr) {
        return '';
    }
    $up = $curr > $prev;
    return sprintf(
        '<span class="delta %s">%s%d %s vs. previous report</span>',
        $up ? 'delta-up' : 'delta-down',
        $up ? '▲' : '▼',
        abs($curr - $prev),
        htmlspecialchars($label)
    );
}
