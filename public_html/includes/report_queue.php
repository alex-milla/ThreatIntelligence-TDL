<?php
/**
 * Manual report queue.
 *
 * The analyst reviews domains (keyword match lists / notifications), validates
 * WHOIS + VirusTotal and marks the ones to include in the next report. Marked
 * domains are per-user and persist until a report is generated, so a report can
 * be produced days later and will contain everything queued since the previous
 * generation (the "daily report").
 */
require_once __DIR__ . '/db.php';

/** Normalise a domain for queue storage/lookup. */
function reportQueueNormalizeDomain(string $domain): string {
    return strtolower(trim($domain));
}

/**
 * Of the given domains, return the subset that belongs to one of the user's
 * keyword matches (guards the queue against arbitrary writes).
 *
 * @param array $domains
 * @return array<string> lowercased valid domains
 */
function reportQueueValidDomains(PDO $db, int $userId, array $domains): array {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $sql = "SELECT DISTINCT m.domain
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain IN ($placeholders)";
    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$userId], $clean));
    return array_map('strtolower', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

/**
 * Add (or re-add) domains to the user's report queue. Returns how many were
 * valid and queued. Re-queueing a previously reported domain resets it to
 * pending.
 */
function reportQueueAdd(PDO $db, int $userId, array $domains): int {
    $valid = reportQueueValidDomains($db, $userId, $domains);
    if (empty($valid)) {
        return 0;
    }
    $stmt = $db->prepare("INSERT OR REPLACE INTO report_queue
        (user_id, domain, added_at, reported_at, report_id)
        VALUES (?, ?, CURRENT_TIMESTAMP, NULL, NULL)");
    foreach ($valid as $domain) {
        $stmt->execute([$userId, $domain]);
    }
    return count($valid);
}

/**
 * Remove domains from the user's report queue (pending or already reported).
 * Returns the number of rows deleted.
 */
function reportQueueRemove(PDO $db, int $userId, array $domains): int {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return 0;
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("DELETE FROM report_queue WHERE user_id = ? AND domain IN ($placeholders)");
    $stmt->execute(array_merge([$userId], $clean));
    return $stmt->rowCount();
}

/** Number of pending (not yet reported) domains for the user. */
function reportQueuePendingCount(PDO $db, int $userId): int {
    $stmt = $db->prepare("SELECT COUNT(*) FROM report_queue WHERE user_id = ? AND reported_at IS NULL");
    $stmt->execute([$userId]);
    return (int)$stmt->fetchColumn();
}

/**
 * Pending domains with the keywords that matched them (for the report-queue
 * table). One row per domain; `keywords` is a comma-separated list.
 */
function reportQueuePending(PDO $db, int $userId, int $limit = 2000): array {
    $stmt = $db->prepare(
        "SELECT q.domain, q.added_at,
                (SELECT GROUP_CONCAT(kk.keyword, ', ')
                   FROM (SELECT DISTINCT k.keyword
                           FROM matches m JOIN keywords k ON k.id = m.keyword_id
                          WHERE k.user_id = ? AND m.domain = q.domain
                          ORDER BY k.keyword) kk) AS keywords
           FROM report_queue q
          WHERE q.user_id = ? AND q.reported_at IS NULL
          ORDER BY q.added_at ASC, q.domain ASC
          LIMIT " . (int)$limit
    );
    $stmt->execute([$userId, $userId]);
    return $stmt->fetchAll();
}

/** Domains currently pending for the user (lowercased list). */
function reportQueuePendingDomains(PDO $db, int $userId): array {
    $stmt = $db->prepare("SELECT domain FROM report_queue WHERE user_id = ? AND reported_at IS NULL ORDER BY added_at ASC");
    $stmt->execute([$userId]);
    return array_map('strtolower', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

/**
 * Queue status for a set of domains (used to paint the "Queued" badges).
 *
 * @return array<string,array{added_at:?string,reported_at:?string}> keyed by domain
 */
function reportQueueStatus(PDO $db, int $userId, array $domains): array {
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("SELECT domain, added_at, reported_at FROM report_queue WHERE user_id = ? AND domain IN ($placeholders)");
    $stmt->execute(array_merge([$userId], $clean));
    $out = [];
    foreach ($stmt->fetchAll() as $row) {
        $out[strtolower($row['domain'])] = [
            'added_at' => $row['added_at'],
            'reported_at' => $row['reported_at'],
        ];
    }
    return $out;
}

/**
 * Stamp the given pending domains as reported by a generated report. When
 * $domains is null, every pending domain of the user is stamped (the "daily
 * report" consumes the whole queue).
 */
function reportQueueMarkReported(PDO $db, int $userId, int $reportId, ?array $domains = null): int {
    $now = gmdate('Y-m-d H:i:s');
    if ($domains === null) {
        $stmt = $db->prepare("UPDATE report_queue SET reported_at = ?, report_id = ? WHERE user_id = ? AND reported_at IS NULL");
        $stmt->execute([$now, $reportId, $userId]);
        return $stmt->rowCount();
    }
    $clean = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d !== '') {
            $clean[$d] = true;
        }
    }
    $clean = array_keys($clean);
    if (empty($clean)) {
        return 0;
    }
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("UPDATE report_queue SET reported_at = ?, report_id = ?
        WHERE user_id = ? AND reported_at IS NULL AND domain IN ($placeholders)");
    $stmt->execute(array_merge([$now, $reportId, $userId], $clean));
    return $stmt->rowCount();
}
