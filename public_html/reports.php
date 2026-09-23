<?php
/**
 * Report builder + saved-report history.
 *
 * Builder tab: users pick a set of keywords (marking them on the table or by
 * selecting a group) and generate a printable report. Generating stores an
 * immutable snapshot in `report_history` and opens it.
 *
 * History tab: the stored reports can be reviewed (filtered by keyword group)
 * and cleaned up (one, selected, or all shown).
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_builder.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

/** Build a /reports.php URL preserving tab + group. */
function reportsUrl(string $tab, string $group): string {
    $q = ['tab' => $tab];
    if ($group !== '' && $group !== 'all') {
        $q['group'] = $group;
    }
    return '/reports.php?' . http_build_query($q);
}

/** Automatic, human-readable report title. */
function buildReportTitle(array $data): string {
    $when = fmt_date((string)($data['generated_at'] ?? gmdate('Y-m-d H:i:s')));
    if (($data['group_name'] ?? '') !== '') {
        return 'Group "' . $data['group_name'] . '" — ' . $when;
    }
    $n = count($data['report'] ?? []);
    return $n . ' keyword(s) — ' . $when;
}

/* ============================ POST actions ============================ */

// Generate + save report(s) from the manual queue, assigned to their keyword
// group. A specific group generates only that group; "All" generates one report
// per group with pending domains.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'generate_queue_report') {
    $requested = (string)($_POST['group'] ?? 'all');
    $buckets = reportQueuePendingByGroup($db, $userId);

    if ($requested === 'all') {
        $targets = $buckets;
    } else {
        $gk = ($requested === 'ungrouped') ? '' : (ctype_digit($requested) ? (string)(int)$requested : '');
        $targets = isset($buckets[$gk]) ? [$gk => $buckets[$gk]] : [];
    }

    if (empty($targets)) {
        $_SESSION['flash_error'] = 'The report queue is empty or its domains no longer match your keywords.';
        header('Location: /reports.php');
        exit;
    }

    $generatedIds = [];
    foreach ($targets as $gk => $bucket) {
        $data = buildReportFromQueue($db, $userId, $bucket['domains'], (string)$gk);
        if (!$data || empty($data['report'])) {
            continue;
        }
        $blob = gzcompress(json_encode($data, JSON_UNESCAPED_UNICODE));
        $when = fmt_date((string)$data['generated_at']);
        $title = ($data['group_name'] !== '') ? ('Group "' . $data['group_name'] . '" — ' . $when) : ('Ungrouped — ' . $when);
        $db->prepare("INSERT INTO report_history
                (user_id, title, group_id, group_name, filters, keywords, data, domains, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
           ->execute([
                $userId,
                $title,
                $data['group_id'],
                $data['group_name'],
                json_encode($data['filters']),
                json_encode($data['keywords']),
                $blob,
                (int)$data['domains'],
                gmdate('c'),
           ]);
        $reportId = (int)$db->lastInsertId();
        // Consume only this group's queue entries.
        reportQueueMarkReported($db, $userId, $reportId, (string)$gk);
        $generatedIds[] = $reportId;
    }

    if (empty($generatedIds)) {
        $_SESSION['flash_error'] = 'The report queue is empty or its domains no longer match your keywords.';
        header('Location: /reports.php');
        exit;
    }

    if (count($generatedIds) === 1) {
        header('Location: /report_view.php?id=' . $generatedIds[0]);
        exit;
    }

    $_SESSION['flash_message'] = count($generatedIds) . ' report(s) generated from the queue.';
    header('Location: /reports.php?tab=history');
    exit;
}

// Remove a single (domain, group) entry from the report queue.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'remove_queue_domain') {
    $domain = strtolower(trim((string)($_POST['domain'] ?? '')));
    if ($domain !== '') {
        $groupKey = array_key_exists('group_key', $_POST) ? (string)$_POST['group_key'] : null;
        reportQueueRemove($db, $userId, [$domain], $groupKey);
        $_SESSION['flash_message'] = 'Domain removed from the report queue.';
    }
    header('Location: /reports.php');
    exit;
}

// Empty the whole pending queue.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_queue') {
    $pending = reportQueuePendingDomains($db, $userId);
    if ($pending) {
        reportQueueRemove($db, $userId, $pending);
    }
    $_SESSION['flash_message'] = count($pending) . ' domain(s) removed from the report queue.';
    header('Location: /reports.php');
    exit;
}

// Delete a single saved report.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_report') {
    $rid = (int)($_POST['report_id'] ?? 0);
    $db->prepare("DELETE FROM report_history WHERE id = ? AND user_id = ?")->execute([$rid, $userId]);
    $_SESSION['flash_message'] = 'Report deleted.';
    header('Location: ' . reportsUrl('history', (string)($_POST['return_group'] ?? 'all')));
    exit;
}

// Delete selected saved reports.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_reports') {
    $ids = array_values(array_filter(array_map('intval', (array)($_POST['ids'] ?? [])), fn($v) => $v > 0));
    if ($ids) {
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $db->prepare("DELETE FROM report_history WHERE user_id = ? AND id IN ($ph)")
           ->execute(array_merge([$userId], $ids));
    }
    $_SESSION['flash_message'] = count($ids) . ' report(s) deleted.';
    header('Location: ' . reportsUrl('history', (string)($_POST['return_group'] ?? 'all')));
    exit;
}

// Delete every report shown (respects the active group filter).
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_all_reports') {
    $g = (string)($_POST['return_group'] ?? 'all');
    if ($g === 'ungrouped') {
        $db->prepare("DELETE FROM report_history WHERE user_id = ? AND group_id IS NULL")->execute([$userId]);
    } elseif (ctype_digit($g)) {
        $db->prepare("DELETE FROM report_history WHERE user_id = ? AND group_id = ?")->execute([$userId, (int)$g]);
    } else {
        $db->prepare("DELETE FROM report_history WHERE user_id = ?")->execute([$userId]);
    }
    $_SESSION['flash_message'] = 'Shown reports deleted.';
    header('Location: ' . reportsUrl('history', $g));
    exit;
}

// Create group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_group') {
    $name = trim($_POST['group_name'] ?? '');
    if ($name === '') {
        $_SESSION['flash_error'] = 'Group name cannot be empty.';
    } elseif (mb_strlen($name) > 60) {
        $_SESSION['flash_error'] = 'Group name is too long (max 60 characters).';
    } else {
        $db->prepare("INSERT INTO keyword_groups (user_id, name) VALUES (?, ?)")->execute([$userId, $name]);
        $_SESSION['flash_message'] = 'Group created.';
    }
    header('Location: /reports.php');
    exit;
}

// Delete group (its keywords become ungrouped)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    $db->prepare("UPDATE keywords SET group_id = NULL WHERE group_id = ? AND user_id = ?")->execute([$groupId, $userId]);
    $db->prepare("DELETE FROM keyword_groups WHERE id = ? AND user_id = ?")->execute([$groupId, $userId]);
    // Queued entries tied to the removed group would be orphaned; drop them.
    $db->prepare("DELETE FROM report_queue WHERE user_id = ? AND group_key = ?")->execute([$userId, (string)$groupId]);
    $_SESSION['flash_message'] = 'Group deleted. Its keywords are now ungrouped.';
    header('Location: /reports.php');
    exit;
}

// Rename group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'rename_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    $name = trim($_POST['name'] ?? '');
    if ($name === '' || mb_strlen($name) > 60) {
        $_SESSION['flash_error'] = 'Invalid group name.';
    } else {
        $db->prepare("UPDATE keyword_groups SET name = ? WHERE id = ? AND user_id = ?")->execute([$name, $groupId, $userId]);
        $_SESSION['flash_message'] = 'Group renamed.';
    }
    header('Location: /reports.php?group=' . (int)$groupId);
    exit;
}

// Assign one keyword to a group (empty value = ungrouped)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'set_group') {
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $groupId = (($_POST['group_id'] ?? '') === '') ? null : (int)$_POST['group_id'];
    if ($groupId !== null) {
        $chk = $db->prepare("SELECT COUNT(*) FROM keyword_groups WHERE id = ? AND user_id = ?");
        $chk->execute([$groupId, $userId]);
        if (!(int)$chk->fetchColumn()) {
            $groupId = null;
        }
    }
    $db->prepare("UPDATE keywords SET group_id = ? WHERE id = ? AND user_id = ?")->execute([$groupId, $keywordId, $userId]);
    header('Location: ' . reportsUrl('builder', (string)($_POST['return_group'] ?? 'all')));
    exit;
}

/* ============================ Filters ============================ */

$tab = (string)($_GET['tab'] ?? 'builder');
if (!in_array($tab, ['builder', 'history'], true)) {
    $tab = 'builder';
}

$groupFilter = (string)($_GET['group'] ?? 'all'); // 'all' | 'ungrouped' | numeric id
// Builder: list only keywords with matches from the last sync unless "show all".
$onlyRecent = (string)($_GET['scope'] ?? '') !== 'all';
if ($groupFilter !== 'all' && $groupFilter !== 'ungrouped' && !ctype_digit($groupFilter)) {
    $groupFilter = 'all';
}

// Load groups (shared by both tabs).
$groupStmt = $db->prepare("SELECT id, name FROM keyword_groups WHERE user_id = ? ORDER BY name ASC");
$groupStmt->execute([$userId]);
$groups = $groupStmt->fetchAll();
$groupsById = [];
foreach ($groups as $g) {
    $groupsById[(int)$g['id']] = $g['name'];
}

/* ============================ Builder data ============================ */

$groupCounts = [];
$ungroupedCount = 0;
$totalKeywords = 0;
$keywords = [];
$groupFallback = false;

if ($tab === 'builder') {
    // "Last sync" is defined by discovery date only: a keyword belongs to it when
    // it has matches discovered in the last 24h, excluding explicitly excluded
    // domains. Classification and the WHOIS "registered before the last scan"
    // heuristic do NOT remove a keyword from this list.
    $kwStmt = $db->prepare("SELECT k.id, k.keyword, k.match_count, k.group_id, k.created_at,
        COUNT(CASE WHEN m.id IS NOT NULL
            AND m.discovered_at >= datetime('now', '-1 day')
            AND NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')
        THEN 1 END) AS recent_count
    FROM keywords k
    LEFT JOIN matches m ON m.keyword_id = k.id AND m.is_historical = 0
    WHERE k.user_id = ?
    GROUP BY k.id
    ORDER BY k.keyword ASC");
    $kwStmt->execute([$userId]);
    $allKeywords = $kwStmt->fetchAll();

    $recentKeywords = $onlyRecent
        ? array_values(array_filter($allKeywords, fn($k) => (int)$k['recent_count'] > 0))
        : $allKeywords;

    foreach ($recentKeywords as $k) {
        $key = $k['group_id'] === null ? 'ungrouped' : (string)$k['group_id'];
        $groupCounts[$key] = ($groupCounts[$key] ?? 0) + 1;
    }
    $ungroupedCount = $groupCounts['ungrouped'] ?? 0;
    $totalKeywords = count($recentKeywords);

    $matchesGroup = function ($k) use ($groupFilter) {
        if ($groupFilter === 'ungrouped') {
            return $k['group_id'] === null;
        }
        if (ctype_digit($groupFilter)) {
            return (string)$k['group_id'] === $groupFilter;
        }
        return true;
    };

    $keywords = array_values(array_filter($recentKeywords, $matchesGroup));

    // A group must never come out empty: if it has no last-sync keywords, show
    // all of its keywords instead (with a notice).
    if ($onlyRecent && $groupFilter !== 'all' && empty($keywords)) {
        $fallbackKeywords = array_values(array_filter($allKeywords, $matchesGroup));
        if (!empty($fallbackKeywords)) {
            $groupFallback = true;
            $keywords = $fallbackKeywords;
        }
    }
}

/* ============================ History data ============================ */

$history = [];
$histGroupCounts = [];
$histUngrouped = 0;
$histTotal = 0;

if ($tab === 'history') {
    $hcStmt = $db->prepare("SELECT group_id, COUNT(*) AS cnt FROM report_history WHERE user_id = ? GROUP BY group_id");
    $hcStmt->execute([$userId]);
    foreach ($hcStmt->fetchAll() as $c) {
        $key = $c['group_id'] === null ? 'ungrouped' : (string)$c['group_id'];
        $histGroupCounts[$key] = (int)$c['cnt'];
    }
    $histUngrouped = $histGroupCounts['ungrouped'] ?? 0;
    $histTotal = array_sum($histGroupCounts);

    $hw = "WHERE user_id = ?";
    $hp = [$userId];
    if ($groupFilter === 'ungrouped') {
        $hw .= " AND group_id IS NULL";
    } elseif (ctype_digit($groupFilter)) {
        $hw .= " AND group_id = ?";
        $hp[] = (int)$groupFilter;
    }
    $hStmt = $db->prepare("SELECT id, title, group_id, group_name, keywords, domains, created_at
        FROM report_history $hw ORDER BY created_at DESC, id DESC");
    $hStmt->execute($hp);
    $history = $hStmt->fetchAll();
}

/* ============================ Report queue ============================ */

$queueRows = [];          // rows visible under the active group filter
$queueBuckets = [];       // group_key => bucket (pending per group)
$queueGroupCounts = [];   // group tab counters ('ungrouped' or id => count)
$queueCount = 0;          // distinct pending domains (all groups)
$queueOldest = null;
if ($tab === 'builder') {
    $allQueueRows = reportQueuePendingRows($db, $userId);
    $queueBuckets = reportQueuePendingByGroup($db, $userId);
    $queueCount = reportQueuePendingCount($db, $userId);
    foreach ($allQueueRows as $qr) {
        if ($qr['added_at'] !== null && ($queueOldest === null || $qr['added_at'] < $queueOldest)) {
            $queueOldest = $qr['added_at'];
        }
    }
    foreach ($queueBuckets as $gk => $b) {
        $queueGroupCounts[($gk === '') ? 'ungrouped' : (string)$gk] = $b['count'];
    }
    $queueRows = array_values(array_filter($allQueueRows, function ($qr) use ($groupFilter) {
        if ($groupFilter === 'all') {
            return true;
        }
        if ($groupFilter === 'ungrouped') {
            return $qr['group_key'] === '';
        }
        return $qr['group_key'] === (string)$groupFilter;
    }));
}

// Counts shown on the group tabs depend on the active tab. On the Queue tab
// they are pending domains per group; on History, saved reports per group.
$tabCounts = $tab === 'history' ? $histGroupCounts : $queueGroupCounts;
$tabUngrouped = $tab === 'history' ? $histUngrouped : ($queueGroupCounts['ungrouped'] ?? 0);
$tabTotal = $tab === 'history' ? $histTotal : $queueCount;
$tabBase = '/reports.php?tab=' . $tab;

$pageTitle = 'Reports';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2><i class="material-icons left">assessment</i>Reports</h2>
        <span class="muted">
            <?php if ($tab === 'builder'): ?>
                <?= $queueCount ?> domain(s) pending in the report queue
            <?php else: ?>
                <?= $histTotal ?> saved report(s)
            <?php endif; ?>
        </span>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- Sub-tabs: Builder / History -->
    <div class="report-tabs">
        <a href="/reports.php?tab=builder" class="report-tab <?= $tab === 'builder' ? 'active' : '' ?>"><i class="material-icons tiny left">playlist_add_check</i>Queue</a>
        <a href="/reports.php?tab=history" class="report-tab <?= $tab === 'history' ? 'active' : '' ?>"><i class="material-icons tiny left">history</i>History (<?= $histTotal ?>)</a>
    </div>

    <!-- Group filter tabs -->
    <div class="group-tabs">
        <a href="<?= htmlspecialchars($tabBase) ?>" class="group-tab <?= $groupFilter === 'all' ? 'active' : '' ?>">All (<?= $tabTotal ?>)</a>
        <?php foreach ($groups as $g):
            $gCount = $tabCounts[(string)$g['id']] ?? 0;
            $isActive = $groupFilter === (string)$g['id'];
        ?>
            <span class="group-chip">
                <a href="<?= htmlspecialchars($tabBase . '&group=' . (int)$g['id']) ?>" class="group-tab <?= $isActive ? 'active' : '' ?>"><?= htmlspecialchars($g['name']) ?> (<?= $gCount ?>)</a>
                <?php if ($tab === 'builder'): ?>
                <form method="POST" style="margin: 0; display: inline-flex;" onsubmit="return confirm('Delete group &quot;<?= htmlspecialchars(addslashes($g['name'])) ?>&quot;? Its keywords will become ungrouped.')">
                    <?php csrfField(); ?>
                    <input type="hidden" name="action" value="delete_group">
                    <input type="hidden" name="group_id" value="<?= (int)$g['id'] ?>">
                    <button type="submit" class="group-tab group-delete" title="Delete group"><i class="material-icons tiny">close</i></button>
                </form>
                <?php endif; ?>
            </span>
        <?php endforeach; ?>
        <a href="<?= htmlspecialchars($tabBase . '&group=ungrouped') ?>" class="group-tab <?= $groupFilter === 'ungrouped' ? 'active' : '' ?>">Ungrouped (<?= $tabUngrouped ?>)</a>
    </div>

    <?php if ($tab === 'builder'): ?>

        <p class="muted">Review domains in a keyword's <strong>match list</strong> (or in Notifications), validate WHOIS / VirusTotal and use <strong>Send to report</strong> to mark the ones to include. Each domain is assigned to the keyword group it belongs to; generating a group's report consumes only that group's pending entries.</p>

        <!-- Create group (kept visible) -->
        <form method="POST" class="group-create-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="create_group">
            <div class="input-field">
                <i class="material-icons prefix">create_new_folder</i>
                <input id="group_name" type="text" name="group_name" placeholder=" " maxlength="60" required>
                <label for="group_name">New report group</label>
            </div>
            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">add</i>Add Group</button>
        </form>

        <?php if ($queueCount === 0): ?>
            <div class="notice notice-info"><i class="material-icons">inbox</i>
                <div>No domains in the report queue yet. Open a <a href="/keywords.php"><strong>keyword match list</strong></a>, select domains and click <strong>Send to report</strong>.</div>
            </div>
        <?php else: ?>
            <?php
            if ($groupFilter === 'all') {
                $generateLabel = 'Generate reports for all groups (' . count($queueBuckets) . ')';
            } elseif ($groupFilter === 'ungrouped') {
                $generateLabel = 'Generate report for Ungrouped (' . ($queueGroupCounts['ungrouped'] ?? 0) . ')';
            } else {
                $activeGroupName = $groupsById[(int)$groupFilter] ?? '';
                $generateLabel = 'Generate report for "' . ($activeGroupName !== '' ? $activeGroupName : 'group') . '" (' . ($queueGroupCounts[(string)(int)$groupFilter] ?? 0) . ')';
            }
            ?>
            <div class="section-actions">
                <form method="POST" style="margin: 0;">
                    <?php csrfField(); ?>
                    <input type="hidden" name="action" value="generate_queue_report">
                    <input type="hidden" name="group" value="<?= htmlspecialchars($groupFilter) ?>">
                    <button type="submit" class="btn waves-effect" onclick="return confirm('Generate the report(s) for the selected group(s)? Those queue entries will be marked as reported.')"><i class="material-icons left">print</i><?= htmlspecialchars($generateLabel) ?></button>
                </form>
                <form method="POST" style="margin: 0;" onsubmit="return confirm('Empty the report queue? This removes all pending domains.')">
                    <?php csrfField(); ?>
                    <input type="hidden" name="action" value="clear_queue">
                    <button type="submit" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">clear_all</i>Clear queue</button>
                </form>
                <span class="muted"><?= $queueCount ?> domain(s) pending<?= $queueOldest ? ' since ' . htmlspecialchars(fmt_date((string)$queueOldest)) : '' ?>.</span>
            </div>

            <?php if (empty($queueRows)): ?>
                <p class="muted">No pending domains in this group.</p>
            <?php else: ?>
            <table class="striped highlight responsive-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Report group</th>
                        <th>Keyword(s)</th>
                        <th>Added</th>
                        <th>Remove</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($queueRows as $q): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($q['domain']) ?></strong></td>
                        <td><?= $q['group_name'] !== '' ? htmlspecialchars($q['group_name']) : '<span class="muted">Ungrouped</span>' ?></td>
                        <td><?= htmlspecialchars(implode(', ', $q['keywords'])) ?></td>
                        <td><?= htmlspecialchars(fmt_date((string)$q['added_at'])) ?></td>
                        <td>
                            <form method="POST" style="margin: 0;">
                                <?php csrfField(); ?>
                                <input type="hidden" name="action" value="remove_queue_domain">
                                <input type="hidden" name="domain" value="<?= htmlspecialchars($q['domain']) ?>">
                                <input type="hidden" name="group_key" value="<?= htmlspecialchars($q['group_key']) ?>">
                                <button type="submit" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">close</i>Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        <?php endif; ?>

        <details class="report-groups" style="margin-top: 20px;">
            <summary style="cursor: pointer; font-weight: 600; padding: 6px 0;"><i class="material-icons tiny" style="vertical-align: middle;">folder</i> Assign keywords to groups</summary>
            <p class="muted" style="margin-top: 8px;">Pick the group of each keyword. Saved reports can be filtered by group in the History tab.</p>

            <!-- Scope: last sync vs every keyword -->
            <form method="GET" class="report-scope-form">
                <input type="hidden" name="tab" value="builder">
                <input type="hidden" name="group" value="<?= htmlspecialchars($groupFilter) ?>">
                <label class="check-inline" title="List every keyword, including those without recent matches">
                    <input type="checkbox" name="scope" value="all" <?= $onlyRecent ? '' : 'checked' ?> onchange="this.form.submit()">
                    <span>Show all keywords (not only the last sync)</span>
                </label>
            </form>

            <?php if (empty($keywords)): ?>
                <p class="muted">
                    No keywords in this view<?= $onlyRecent ? ' with matches in the last 24h' : '' ?>.
                    <a href="/keywords.php">Add keywords</a>, switch to another group, or tick
                    <strong>Show all keywords</strong> to see every keyword.
                </p>
            <?php else: ?>
                <?php if ($groupFallback): ?>
                    <div class="alert alert-info"><i class="material-icons left">info</i>No keywords from the last sync in this group; showing <strong>all</strong> of its keywords.</div>
                <?php endif; ?>
                <table class="striped highlight responsive-table">
                    <thead>
                        <tr>
                            <th>Keyword</th>
                            <th>Matches (24h)</th>
                            <th>Report group</th>
                            <th>Added</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($keywords as $k): ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($k['keyword']) ?></strong></td>
                            <td>
                                <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" title="Domains discovered in the last sync (24h)"><?= (int)$k['recent_count'] ?></a><?php if ((int)$k['recent_count'] !== (int)$k['match_count']): ?> <span class="muted" title="Total matches ever">(<?= (int)$k['match_count'] ?> total)</span><?php endif; ?>
                            </td>
                            <td>
                                <form method="POST" style="margin: 0;">
                                    <?php csrfField(); ?>
                                    <input type="hidden" name="action" value="set_group">
                                    <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                                    <input type="hidden" name="return_group" value="<?= htmlspecialchars($groupFilter) ?>">
                                    <select name="group_id" class="browser-default compact" onchange="this.form.submit()">
                                        <option value="" <?= $k['group_id'] === null ? 'selected' : '' ?>>— Ungrouped</option>
                                        <?php foreach ($groups as $g): ?>
                                        <option value="<?= (int)$g['id'] ?>" <?= (string)$k['group_id'] === (string)$g['id'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </form>
                            </td>
                            <td><?= htmlspecialchars(fmt_date($k['created_at'])) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </details>

    <?php else: ?>

        <p class="muted">Saved reports (immutable snapshots). Open one to review or print it, or delete the ones you no longer need. Filter by keyword group above.</p>

        <?php if (empty($history)): ?>
            <p class="muted">No saved reports in this view. Mark domains in a <a href="/keywords.php">keyword match list</a> and generate one from the <a href="/reports.php?tab=builder<?= $groupFilter !== 'all' ? '&group=' . urlencode($groupFilter) : '' ?>">queue</a>.</p>
        <?php else: ?>
            <form method="POST" id="history-bulk-form" style="margin: 0;">
                <?php csrfField(); ?>
                <input type="hidden" name="return_group" value="<?= htmlspecialchars($groupFilter) ?>">
            </form>

            <div class="section-actions">
                <label class="check-inline"><input type="checkbox" id="select-all"><span><strong>Select all</strong></span></label>
                <button type="submit" form="history-bulk-form" name="action" value="delete_reports" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Delete the selected report(s)?')"><i class="material-icons left">delete</i>Delete selected</button>
                <button type="submit" form="history-bulk-form" name="action" value="delete_all_reports" class="btn btn-small btn-outline waves-effect" onclick="return confirm('Delete ALL reports shown (current group filter)? This cannot be undone.')"><i class="material-icons left">delete_sweep</i>Delete all shown</button>
            </div>

            <table class="striped highlight responsive-table">
                <thead>
                    <tr>
                        <th style="width: 30px;"></th>
                        <th>Date</th>
                        <th>Title</th>
                        <th>Group</th>
                        <th>Keywords</th>
                        <th class="num">Domains</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($history as $h): $kwNames = json_decode((string)$h['keywords'], true) ?: []; ?>
                    <tr>
                        <td><label><input type="checkbox" class="row-check" name="ids[]" value="<?= (int)$h['id'] ?>" form="history-bulk-form"><span></span></label></td>
                        <td><?= htmlspecialchars(fmt_date($h['created_at'])) ?></td>
                        <td><a href="/report_view.php?id=<?= (int)$h['id'] ?>" title="Open report"><?= htmlspecialchars($h['title'] !== '' ? $h['title'] : ('Report #' . (int)$h['id'])) ?></a></td>
                        <td><?= ($h['group_name'] !== null && $h['group_name'] !== '') ? htmlspecialchars($h['group_name']) : '<span class="muted">&mdash;</span>' ?></td>
                        <td><?= htmlspecialchars(implode(', ', array_slice($kwNames, 0, 6))) ?><?= count($kwNames) > 6 ? ' …' : '' ?></td>
                        <td class="num"><?= number_format((int)$h['domains']) ?></td>
                        <td>
                            <a href="/report_view.php?id=<?= (int)$h['id'] ?>" class="btn btn-small btn-outline waves-effect"><i class="material-icons left">open_in_new</i>Open</a>
                            <form method="POST" style="display: inline; margin: 0;" onsubmit="return confirm('Delete this report?')">
                                <?php csrfField(); ?>
                                <input type="hidden" name="action" value="delete_report">
                                <input type="hidden" name="report_id" value="<?= (int)$h['id'] ?>">
                                <input type="hidden" name="return_group" value="<?= htmlspecialchars($groupFilter) ?>">
                                <button type="submit" class="btn btn-small btn-danger waves-effect"><i class="material-icons left">delete</i>Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

    <?php endif; ?>
</div>

<script>
// (Report generation now runs from the queue; the old keyword selection script
// was removed with the classic Builder.)
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
