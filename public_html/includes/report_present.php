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

    if ($tag === 'bad' || $verdict === 'malicious') {
        return 'malicious';
    }
    if ($verdict === 'suspicious' || $verdict === 'dga') {
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
        'state' => $verdict,
        'label' => $labels[$verdict] ?? ucfirst($verdict),
        'detail' => $total > 0 ? ($hits . ' of ' . $total . ' engines') : '',
    ];
}

/** Data availability per source (only WHOIS + VirusTotal exist right now). */
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
    return ['whois' => $whois, 'vt' => $vt];
}
