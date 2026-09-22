<?php
/**
 * Shared report helpers.
 *
 * The visibility rules that decide whether a match is shown by default live
 * here so the Notifications list and the Reports use exactly the same
 * definition (historical recheck, tagged good/bad, explicitly excluded, or a
 * WHOIS-validated domain registered before the last successful scan of its TLD).
 */

/**
 * SQL fragments describing the default match visibility.
 *
 * All clauses assume the `matches` table is aliased as `m`. They contain no
 * bound parameters (the day window is cast to an int before interpolation),
 * so they can be concatenated into any query.
 *
 * @return array{good_bad:string,excluded:string,observing:string,old_domain:string,hidden:string}
 */
function matchVisibilityClauses(PDO $db): array {
    $newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));

    $goodBad = "NOT EXISTS (SELECT 1 FROM domain_tags dt WHERE dt.domain = m.domain AND dt.tag IN ('good','bad'))";
    $excluded = "NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')";
    $observing = "EXISTS (SELECT 1 FROM domain_tags dob WHERE dob.domain = m.domain AND dob.tag = 'observing')";
    $oldDomain = "EXISTS (SELECT 1 FROM domain_whois dw JOIN tlds t ON t.name = m.tld "
        . "WHERE dw.domain = m.domain AND t.last_ok_sync IS NOT NULL "
        . "AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) IS NOT NULL "
        . "AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) < datetime(t.last_ok_sync, '-{$newDomainDays} days'))";

    // Excluded domains are hidden outright; good/bad and validated-old domains
    // are hidden unless explicitly under observation.
    $hidden = "m.is_historical = 1"
        . " OR NOT ({$excluded})"
        . " OR NOT ({$goodBad})"
        . " OR (NOT ({$observing}) AND ({$oldDomain}))";

    return [
        'good_bad'   => $goodBad,
        'excluded'   => $excluded,
        'observing'  => $observing,
        'old_domain' => $oldDomain,
        'hidden'     => $hidden,
    ];
}
