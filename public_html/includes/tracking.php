<?php
/**
 * Dormant-domain intelligence tracking helpers (web side).
 *
 * A tracked (domain, keyword) pair is followed for the keyword's tracking
 * window. The worker re-validates it periodically and posts activation signals
 * back; these helpers keep the timestamp/baseline logic in one place.
 */

/** Current UTC time as a SQLite datetime string. */
function trackingNow(): string {
    return gmdate('Y-m-d H:i:s');
}

/** Truncate to a byte length, using mbstring when available. */
function trackingTruncate(string $value, int $len): string {
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $len);
    }
    return substr($value, 0, $len);
}

/** Next check time (UTC) from an interval in hours. */
function trackingNextCheck(int $intervalHours, ?string $fromUtc = null): string {
    $intervalHours = max(1, $intervalHours);
    $base = ($fromUtc !== null && $fromUtc !== '') ? strtotime($fromUtc . ' UTC') : time();
    if ($base === false) {
        $base = time();
    }
    return gmdate('Y-m-d H:i:s', $base + $intervalHours * 3600);
}

/** Add days to a UTC datetime string. */
function trackingAddDays(string $fromUtc, int $days): string {
    $base = strtotime($fromUtc . ' UTC');
    if ($base === false) {
        $base = time();
    }
    return gmdate('Y-m-d H:i:s', $base + max(1, $days) * 86400);
}

/** Age in days from an ISO/SQLite date, or null when unknown. */
function trackingAgeDays(?string $dateUtc): ?int {
    if (!$dateUtc) {
        return null;
    }
    $ts = strtotime((string)$dateUtc);
    if ($ts === false) {
        return null;
    }
    return (int)floor((time() - $ts) / 86400);
}

/** Baseline snapshot of a domain from the local caches. */
function trackingBaseline(PDO $db, string $domain): array {
    $b = ['abusech' => null, 'vt' => null, 'whois' => null];
    $stmt = $db->prepare("SELECT verdict FROM domain_abusech WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    $v = $stmt->fetchColumn();
    $b['abusech'] = ($v === false) ? null : $v;
    $stmt = $db->prepare("SELECT verdict FROM domain_vt WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    $v = $stmt->fetchColumn();
    $b['vt'] = ($v === false) ? null : $v;
    $stmt = $db->prepare("SELECT creation_date, name_servers, registrar FROM domain_whois WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    $row = $stmt->fetch();
    if ($row) {
        $b['whois'] = [
            'creation_date' => $row['creation_date'],
            'name_servers'  => $row['name_servers'],
            'registrar'     => $row['registrar'],
        ];
    }
    return $b;
}

/** Insert a tracking event (best effort). */
function trackingEvent(PDO $db, int $trackingId, string $type, string $detail = ''): void {
    $db->prepare("INSERT INTO domain_tracking_events (tracking_id, type, detail) VALUES (?, ?, ?)")
       ->execute([$trackingId, $type, trackingTruncate($detail, 255)]);
}

/** Mark every tracking row of a domain as activated (used by the results API). */
function trackingActivate(PDO $db, string $domain, string $reason): int {
    $rows = $db->prepare("SELECT id FROM domain_tracking WHERE domain = ? AND status = 'tracking'");
    $rows->execute([$domain]);
    $ids = array_map('intval', $rows->fetchAll(PDO::FETCH_COLUMN));
    if (!$ids) {
        return 0;
    }
    $now = trackingNow();
    $upd = $db->prepare("UPDATE domain_tracking SET status = 'activated', activated_at = ?, activated_reason = ? WHERE id = ?");
    foreach ($ids as $id) {
        $upd->execute([$now, trackingTruncate($reason, 255), $id]);
        trackingEvent($db, $id, 'activated', $reason);
    }
    return count($ids);
}

/** Expire tracking rows whose window elapsed without activation. */
function trackingExpireDue(PDO $db): int {
    $stmt = $db->query("SELECT id FROM domain_tracking WHERE status = 'tracking' AND expires_at IS NOT NULL AND expires_at <= datetime('now')");
    $ids = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    if (!$ids) {
        return 0;
    }
    $upd = $db->prepare("UPDATE domain_tracking SET status = 'dormant' WHERE id = ?");
    foreach ($ids as $id) {
        $upd->execute([$id]);
        trackingEvent($db, $id, 'dormant', 'tracking window elapsed');
    }
    return count($ids);
}

/**
 * Enroll one (domain, keyword) pair if it passes the tracking policy.
 *
 * Domains tagged `excluded` (benign, kept out of reports) ARE enrolled so they
 * can be monitored; `bad` (confirmed malicious) is not. Requires a recent WHOIS
 * creation date and a non-malicious reputation. Returns true when enrolled.
 */
function trackingTryEnroll(PDO $db, array $keyword, string $domain,
                           ?string $firstSeen = null, ?string $creationDate = null): bool {
    $domain = strtolower(trim($domain));
    if ($domain === '' || strlen($domain) > 253 || strpos($domain, '..') !== false
        || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
        return false;
    }

    $stmt = $db->prepare("SELECT tag FROM domain_tags WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    $tag = (string)$stmt->fetchColumn();
    if ($tag === 'bad') {
        return false; // confirmed malicious: not a dormant candidate
    }

    $stmt = $db->prepare("SELECT verdict FROM domain_abusech WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    if (in_array((string)$stmt->fetchColumn(), ['malicious', 'suspicious'], true)) {
        return false;
    }

    if ($creationDate === null || trim($creationDate) === '') {
        $stmt = $db->prepare("SELECT creation_date FROM domain_whois WHERE domain = ? LIMIT 1");
        $stmt->execute([$domain]);
        $creationDate = (string)($stmt->fetchColumn() ?: '');
    }
    $age = trackingAgeDays($creationDate);
    $maxAge = max(1, (int)($keyword['tracking_enroll_max_age_days'] ?? 30));
    if ($age === null || $age > $maxAge) {
        return false;
    }

    $now = trackingNow();
    $expires = trackingAddDays($now, max(1, (int)($keyword['tracking_days'] ?? 90)));
    $baseline = json_encode(trackingBaseline($db, $domain), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $ins = $db->prepare("INSERT OR IGNORE INTO domain_tracking
        (domain, keyword_id, user_id, first_seen, enrolled_at, expires_at, status, baseline, next_check_at)
        VALUES (?, ?, ?, ?, ?, ?, 'tracking', ?, ?)");
    $ins->execute([$domain, (int)$keyword['id'], (int)$keyword['user_id'], $firstSeen ?: null, $now, $expires, $baseline, $now]);
    if ($ins->rowCount() > 0) {
        $note = 'age ' . $age . 'd' . ($tag === 'excluded' ? ' (excluded)' : '');
        trackingEvent($db, (int)$db->lastInsertId(), 'enrolled', $note);
        return true;
    }
    return false; // already tracked
}

/**
 * Reactivate an excluded domain when Intelligence detects movement: swap its
 * `excluded` tag for `observing` (visible again and included in reports) with a
 * note. Returns true when the tag was changed.
 */
function trackingReactivate(PDO $db, string $domain, string $reason): bool {
    $stmt = $db->prepare("SELECT tag FROM domain_tags WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    if ((string)$stmt->fetchColumn() !== 'excluded') {
        return false;
    }
    $db->prepare("UPDATE domain_tags SET tag = 'observing', note = ? WHERE domain = ?")
       ->execute([trackingTruncate('Intelligence: ' . $reason, 255), $domain]);
    return true;
}
