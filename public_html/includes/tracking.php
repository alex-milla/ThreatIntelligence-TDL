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
