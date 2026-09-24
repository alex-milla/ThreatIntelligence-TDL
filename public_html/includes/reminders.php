<?php
/**
 * Per-user dismissible reminders.
 *
 * Currently one reminder: a monthly prompt on the Dashboard to review the
 * `excluded` domains (which Intelligence keeps following). It appears from the
 * last day of the month onwards and stays until dismissed; the dismissal is kept
 * per user and per review month, so it comes back at the next month end.
 */
require_once __DIR__ . '/db.php';

const REMINDER_TZ = 'Europe/Madrid';

/**
 * Key (YYYY-MM) of the month whose review is pending.
 *
 * On the last day of the month it is the current month; on any other day it is
 * the month whose last day already passed (the previous one).
 */
function excludedReviewMonthKey(string $tz = REMINDER_TZ, ?DateTimeInterface $now = null): string {
    $zone = new DateTimeZone($tz);
    $dt = $now
        ? DateTimeImmutable::createFromInterface($now)->setTimezone($zone)
        : new DateTimeImmutable('now', $zone);
    if ((int)$dt->format('j') !== (int)$dt->format('t')) {
        $dt = $dt->modify('first day of this month')->modify('-1 day');
    }
    return $dt->format('Y-m');
}

/** Validate a reminder key handed back by the client. */
function reminderKeyValid(string $key): bool {
    return (bool)preg_match('/^monthly_excluded:\d{4}-\d{2}$/', $key);
}

/**
 * Whether the monthly excluded-domain review should be shown to the user.
 * Fills $key (reminder key) and $count (excluded domains) by reference.
 */
function excludedReviewDue(PDO $db, int $userId, ?string &$key = null, ?int &$count = null): bool {
    $key = 'monthly_excluded:' . excludedReviewMonthKey();
    $stmt = $db->prepare("SELECT 1 FROM user_reminders WHERE user_id = ? AND key = ? LIMIT 1");
    $stmt->execute([$userId, $key]);
    if ($stmt->fetchColumn()) {
        $count = 0;
        return false;
    }
    $c = $db->prepare("SELECT COUNT(DISTINCT m.domain)
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        JOIN domain_tags dt ON dt.domain = m.domain AND dt.tag = 'excluded'
        WHERE k.user_id = ?");
    $c->execute([$userId]);
    $count = (int)$c->fetchColumn();
    return $count > 0;
}

/** Persist the dismissal of a reminder key for a user. */
function reminderDismiss(PDO $db, int $userId, string $key): void {
    $db->prepare("INSERT OR IGNORE INTO user_reminders (user_id, key, dismissed_at) VALUES (?, ?, ?)")
       ->execute([$userId, $key, gmdate('c')]);
}
