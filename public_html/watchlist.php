<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_present.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

// Remove from watchlist
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'remove') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $db->prepare("DELETE FROM watchlist WHERE id = ? AND user_id = ?")->execute([$id, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Update note
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_note') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $note = trim($_POST['note'] ?? '');
    $db->prepare("UPDATE watchlist SET note = ? WHERE id = ? AND user_id = ?")->execute([$note, $id, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Set group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'set_group') {
    $id = (int)($_POST['watch_id'] ?? 0);
    $groupId = $_POST['group_id'] === '' ? null : (int)$_POST['group_id'];
    $db->prepare("UPDATE watchlist SET group_id = ? WHERE id = ? AND user_id = ?")->execute([$groupId, $id, $userId]);
    $redirect = '/watchlist.php';
    if (!empty($_GET['group'])) $redirect .= '?group=' . urlencode($_GET['group']);
    header('Location: ' . $redirect);
    exit;
}

// Create group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_group') {
    $name = trim($_POST['group_name'] ?? '');
    if ($name !== '') {
        $db->prepare("INSERT INTO watchlist_groups (user_id, name) VALUES (?, ?)") ->execute([$userId, $name]);
    }
    header('Location: /watchlist.php');
    exit;
}

// Delete group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    // Move domains to ungrouped first
    $db->prepare("UPDATE watchlist SET group_id = NULL WHERE group_id = ? AND user_id = ?") ->execute([$groupId, $userId]);
    $db->prepare("DELETE FROM watchlist_groups WHERE id = ? AND user_id = ?") ->execute([$groupId, $userId]);
    header('Location: /watchlist.php');
    exit;
}

// Group filter: empty means ungrouped (group_id IS NULL)
$groupFilter = $_GET['group'] ?? '';

// Load groups
$groupStmt = $db->prepare("SELECT id, name FROM watchlist_groups WHERE user_id = ? ORDER BY name ASC");
$groupStmt->execute([$userId]);
$groups = $groupStmt->fetchAll();
$groupsById = [];
foreach ($groups as $g) {
    $groupsById[(int)$g['id']] = $g['name'];
}

// Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;

// Build WHERE: default view shows only ungrouped domains
$where = "WHERE w.user_id = ?";
$params = [$userId];

if ($groupFilter === '' || $groupFilter === '0') {
    $where .= " AND w.group_id IS NULL";
} elseif (ctype_digit($groupFilter)) {
    $where .= " AND w.group_id = ?";
    $params[] = (int)$groupFilter;
}

// Count total
$totalStmt = $db->prepare("SELECT COUNT(*) FROM watchlist w $where");
$totalStmt->execute($params);
$total = (int)$totalStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

// Fetch
$stmt = $db->prepare("SELECT w.id, w.domain, w.note, w.group_id, w.created_at FROM watchlist w $where ORDER BY w.created_at DESC LIMIT ? OFFSET ?");
$stmt->execute(array_merge($params, [$perPage, $offset]));
$items = $stmt->fetchAll();

// "New domain" window (same rule as the rest of the app) + report review rules.
$defaultNewDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
$rules = reportReviewRules($db);

// Full WHOIS for the visible rows (used by the detail block).
$domainWhois = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date, creation_ts, expiration_date, registrar,
            name_servers, status, source, updated_at
        FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
    }
}

// Cached VirusTotal data for the visible rows (detail block).
$domainVt = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $vtStmt = $db->prepare("SELECT domain, verdict, malicious, suspicious, harmless, undetected,
            reputation, last_analysis_date, checked_at
        FROM domain_vt WHERE domain IN ($placeholders)");
    $vtStmt->execute($domains);
    foreach ($vtStmt->fetchAll() as $v) {
        $domainVt[$v['domain']] = $v;
    }
}

// Load domain tags
$domainTags = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $tagStmt = $db->prepare("SELECT domain, tag, note FROM domain_tags WHERE domain IN ($placeholders)");
    $tagStmt->execute($domains);
    foreach ($tagStmt->fetchAll() as $t) {
        $domainTags[$t['domain']] = $t;
    }
}

// Match context for the visible rows: all the keywords that matched each domain
// (a watchlist domain may match several) and the earliest match, used for the
// first_seen / discovered / source / historical fields of the detail block.
$domainMatches = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $mStmt = $db->prepare("SELECT m.domain, m.first_seen, m.discovered_at, m.is_historical, m.source, k.keyword
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        WHERE k.user_id = ? AND m.domain IN ($placeholders)
        ORDER BY m.discovered_at ASC, m.domain ASC");
    $mStmt->execute(array_merge([$userId], $domains));
    foreach ($mStmt->fetchAll() as $mrow) {
        $d = $mrow['domain'];
        if (!isset($domainMatches[$d])) {
            $domainMatches[$d] = ['keywords' => [], 'rep' => $mrow];
        }
        if (!in_array($mrow['keyword'], $domainMatches[$d]['keywords'], true)) {
            $domainMatches[$d]['keywords'][] = $mrow['keyword'];
        }
    }
}

// Count per group for badges
$groupCounts = [];
$countStmt = $db->prepare("SELECT group_id, COUNT(*) as cnt FROM watchlist WHERE user_id = ? GROUP BY group_id");
$countStmt->execute([$userId]);
foreach ($countStmt->fetchAll() as $c) {
    $groupCounts[$c['group_id'] ?? 'ungrouped'] = (int)$c['cnt'];
}
$ungroupedCount = $groupCounts['ungrouped'] ?? 0;
$totalAll = array_sum($groupCounts);

$pageTitle = 'Watchlist';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2><i class="material-icons left">star</i>Watchlist</h2>
        <span class="muted"><?= $totalAll ?> domain(s)</span>
    </div>
    <p class="muted">Private list of domains you are tracking for monitoring over time. Notes are personal and not shared with other users.</p>

    <?php if (empty($items) && empty($groups)): ?>
        <p class="muted">Your watchlist is empty. Add domains from the <a href="/notifications.php">Notifications</a> page or from any domain modal.</p>
    <?php else: ?>

        <!-- Group tabs -->
        <div class="group-tabs">
            <a href="/watchlist.php" class="group-tab <?= $groupFilter === '' || $groupFilter === '0' ? 'active' : '' ?>">Ungrouped (<?= $ungroupedCount ?>)</a>
            <?php foreach ($groups as $g): 
                $gCount = $groupCounts[(string)$g['id']] ?? 0;
                $isActive = $groupFilter === (string)$g['id'];
            ?>
                <span class="group-chip">
                    <a href="/watchlist.php?group=<?= (int)$g['id'] ?>" class="group-tab <?= $isActive ? 'active' : '' ?>"><?= htmlspecialchars($g['name']) ?> (<?= $gCount ?>)</a>
                    <form method="POST" style="margin: 0; display: inline-flex;" onsubmit="return confirm('Delete group &quot;<?= htmlspecialchars(addslashes($g['name'])) ?>&quot;? Domains will become ungrouped.')">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="delete_group">
                        <input type="hidden" name="group_id" value="<?= (int)$g['id'] ?>">
                        <button type="submit" class="group-tab group-delete" title="Delete group"><i class="material-icons tiny">close</i></button>
                    </form>
                </span>
            <?php endforeach; ?>
        </div>

        <!-- Create group form -->
        <form method="POST" class="group-create-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="create_group">
            <div class="input-field">
                <i class="material-icons prefix">create_new_folder</i>
                <input id="group_name" type="text" name="group_name" placeholder=" " required>
                <label for="group_name">New group name</label>
            </div>
            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">add</i>Add Group</button>
        </form>

        <?php if (empty($items)): ?>
            <p>No domains in this group.</p>
        <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Created</th>
                    <th>Group</th>
                    <th>Note</th>
                    <th>Added</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php $repSymbol = ['malicious' => '●', 'suspicious' => '⚠', 'dga' => '⚠', 'clean' => '✓', 'not_checked' => '○', 'unproven' => '○']; ?>
                <?php foreach ($items as $item):
                    $whoisRow = $domainWhois[$item['domain']] ?? null;
                    $vtRow = $domainVt[$item['domain']] ?? null;
                    $dtag = $domainTags[$item['domain']] ?? null;
                    $match = $domainMatches[$item['domain']] ?? null;

                    $creationDate = $whoisRow['creation_date'] ?? null;
                    $creationDisplay = $creationDate ? date('Y-m-d', strtotime($creationDate)) : '—';

                    $tagVal = (string)($dtag['tag'] ?? '');
                    $tagLabels = ['good' => 'GOOD', 'bad' => 'BAD', 'observing' => 'OBSERVING'];
                    $hasTag = isset($tagLabels[$tagVal]);
                    $tagCell = $hasTag
                        ? '<span class="tag-chip ' . $tagVal . '">' . $tagLabels[$tagVal] . '</span>'
                        : '<span class="muted">&mdash;</span>';
                    $tagBadge = $hasTag ? ' ' . $tagCell : '';

                    $isNew = false;
                    if ($creationDate) {
                        $ts = strtotime($creationDate);
                        $isNew = $ts && $ts > strtotime("-{$defaultNewDays} days");
                    }

                    $ns = (!empty($whoisRow['name_servers'])) ? (json_decode((string)$whoisRow['name_servers'], true) ?: []) : [];
                    $dot = strrpos($item['domain'], '.');
                    $tld = ($dot !== false) ? substr($item['domain'], $dot + 1) : '';
                    $keywordsList = $match['keywords'] ?? [];
                    $keywordsLabel = $keywordsList ? implode(', ', $keywordsList) : '';

                    // Same snapshot shape the report presentation helpers expect.
                    $present = [
                        'domain'             => $item['domain'],
                        'tld'                => $tld,
                        'discovered_at'      => $match['rep']['discovered_at'] ?? null,
                        'first_seen'         => $match['rep']['first_seen'] ?? null,
                        'is_historical'      => $match['rep']['is_historical'] ?? 0,
                        'source'             => $match['rep']['source'] ?? null,
                        'tag'                => $tagVal,
                        'tag_note'           => $dtag['note'] ?? null,
                        'in_watchlist'       => 1,
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
                        '_ns'                => $ns,
                        '_is_new'            => $isNew,
                    ];
                    $age = reportDomainAge($present['creation_date'], gmdate('Y-m-d H:i:s'));
                    $status = reportDomainStatus($present, $rules);
                    $rep = reportReputationContextual(reportReputation($present), $age);
                    $avail = reportAvailability($present);
                    $whoisInfo = $avail['whois'];
                    $risk = reportRiskAssessment($present, $status, $avail);
                    $ttdH = reportTimeToDetectHours($present);
                    $timeline = reportTimeline($present, '');
                    $rawJson = htmlspecialchars(json_encode($present, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                    $sourceLabel = (($present['source'] ?? '') === 'ct') ? 'OpenINTEL' : ((($present['source'] ?? '') !== '') ? 'CZDS' : '—');
                    $domainArg = htmlspecialchars(addslashes($item['domain']));
                ?>
                <tr data-domain="<?= htmlspecialchars($item['domain']) ?>">
                    <td>
                        <a href="javascript:void(0)" class="domain-link" onclick="toggleWlDetail(this)" aria-expanded="false"><?= htmlspecialchars($item['domain']) ?></a><?= $tagBadge ?>
                    </td>
                    <td><?= htmlspecialchars($creationDisplay) ?></td>
                    <td>
                        <form method="POST" style="margin: 0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="set_group">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <select name="group_id" class="browser-default compact" onchange="this.form.submit()">
                                <option value="" <?= $item['group_id'] === null ? 'selected' : '' ?>>— Ungrouped</option>
                                <?php foreach ($groups as $g): ?>
                                <option value="<?= (int)$g['id'] ?>" <?= $item['group_id'] == $g['id'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </form>
                    </td>
                    <td>
                        <form method="POST" style="margin: 0; display: flex; gap: 6px; align-items: center;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="update_note">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <input type="text" name="note" value="<?= htmlspecialchars($item['note'] ?? '') ?>" placeholder="Add a note..." class="browser-default compact" style="flex: 1; min-width: 120px;">
                            <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">save</i>Save</button>
                        </form>
                    </td>
                    <td><?= htmlspecialchars(fmt_date($item['created_at'])) ?></td>
                    <td>
                        <form method="POST" style="margin: 0;" onsubmit="return confirm('Remove this domain from your watchlist?')">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="remove">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect"><i class="material-icons left">delete</i>Remove</button>
                        </form>
                    </td>
                </tr>
                <tr class="domain-detail-row" style="display:none;">
                    <td colspan="6">
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
                                        <div><dt>Last analysis</dt><dd><?= htmlspecialchars(reportFormatDate($present['last_analysis_date'] ?? null)) ?></dd></div>
                                        <div><dt>Checked</dt><dd><?= !empty($present['vt_checked_at']) ? htmlspecialchars(fmt_date((string)$present['vt_checked_at'])) : '<span class="muted">&mdash;</span>' ?></dd></div>
                                        <div><dt>Tag</dt><dd><?= $tagCell ?></dd></div>
                                        <div><dt>Watchlist</dt><dd>Yes</dd></div>
                                    </dl>
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
                                <button type="button" class="btn btn-small btn-outline good waves-effect" onclick="tagDomain('<?= $domainArg ?>', 'good')">Mark Good</button>
                                <button type="button" class="btn btn-small btn-outline bad waves-effect" onclick="tagDomain('<?= $domainArg ?>', 'bad')">Mark Bad</button>
                                <button type="button" class="btn btn-small btn-outline warning waves-effect" onclick="tagDomain('<?= $domainArg ?>', 'observing')"><i class="material-icons left">help_outline</i>Insufficient info</button>
                                <button type="button" class="btn btn-small btn-danger waves-effect" onclick="tagDomain('<?= $domainArg ?>', '')">Clear</button>
                                <button type="button" class="btn btn-small waves-effect" onclick="wlFetchWhois('<?= $domainArg ?>')"><i class="material-icons left">cloud_download</i>Fetch WHOIS (worker)</button>
                                <button type="button" class="btn btn-small waves-effect" onclick="wlCheckVt('<?= $domainArg ?>')"><i class="material-icons left">verified_user</i>Check VirusTotal</button>
                                <a class="btn btn-small btn-outline info waves-effect" href="https://www.virustotal.com/gui/domain/<?= rawurlencode($item['domain']) ?>" target="_blank" rel="noopener"><i class="material-icons left">shield</i>Open in VirusTotal</a>
                                <button type="button" class="btn btn-small btn-danger waves-effect" onclick="toggleWatchlist('<?= $domainArg ?>')"><i class="material-icons left">star_border</i>Remove from Watchlist</button>
                            </div>
                            <details class="dd-raw">
                                <summary>Raw data</summary>
                                <pre><?= $rawJson ?></pre>
                            </details>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="pager">
            <span class="pagination-info">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> domains
            </span>
            <ul class="pagination">
                <?php if ($page > 1): ?>
                    <li class="waves-effect"><a href="/watchlist.php?page=<?= $page - 1 ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Previous page"><i class="material-icons">chevron_left</i></a></li>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <li class="active"><a href="#!"><?= $p ?></a></li>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <li class="waves-effect"><a href="/watchlist.php?page=<?= $p ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>"><?= $p ?></a></li>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <li class="disabled"><a href="#!">…</a></li>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <li class="waves-effect"><a href="/watchlist.php?page=<?= $page + 1 ?><?= $groupFilter !== '' ? '&group=' . urlencode($groupFilter) : '' ?>" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php else: ?>
                    <li class="disabled"><a href="#!" aria-label="Next page"><i class="material-icons">chevron_right</i></a></li>
                <?php endif; ?>
            </ul>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<script>
function toggleWlDetail(link) {
    var row = link.closest('tr');
    if (!row) return;
    var detail = row.nextElementSibling;
    if (!detail || !detail.classList.contains('domain-detail-row')) return;
    var open = detail.style.display === 'none' || detail.style.display === '';
    detail.style.display = open ? 'table-row' : 'none';
    link.setAttribute('aria-expanded', open ? 'true' : 'false');
}
function wlCsrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : '';
}
function tagDomain(domain, tag) {
    fetch('/ajax_tag_domain.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain, tag: tag})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            window.location.reload();
        } else {
            alert(data.error || 'Failed to tag domain');
        }
    })
    .catch(() => alert('Failed to tag domain'));
}
function toggleWatchlist(domain) {
    fetch('/ajax_watchlist.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            // The domain's watchlist membership changed, so refresh the list.
            window.location.reload();
        } else {
            alert(data.error || 'Failed to update watchlist');
        }
    })
    .catch(() => alert('Failed to update watchlist'));
}
// Queue a WHOIS refresh on the worker and reload once the result is cached.
function wlFetchWhois(domain) {
    fetch('/ajax_whois_request.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': wlCsrf()},
        body: JSON.stringify({domain: domain, force: true})
    })
    .then(r => r.json())
    .then(function (res) {
        if (!res.success) throw new Error(res.error || 'request failed');
        wlPollWhois(res.command_id, domain, 0);
    })
    .catch(function (e) { alert('WHOIS request failed: ' + e.message); });
}
function wlPollWhois(commandId, domain, tries) {
    if (tries > 45) { alert('Timed out waiting for the worker.'); return; }
    fetch('/ajax_whois_result.php?command_id=' + encodeURIComponent(commandId || '') + '&domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(function (data) {
            if (data.whois) { window.location.reload(); return; }
            if (data.command_status === 'failed' || data.command_status === 'cancelled') {
                alert('Worker could not fetch WHOIS (' + data.command_status + ').');
                return;
            }
            setTimeout(function () { wlPollWhois(commandId, domain, tries + 1); }, 4000);
        })
        .catch(function () { setTimeout(function () { wlPollWhois(commandId, domain, tries + 1); }, 6000); });
}
// Queue a VirusTotal check on the worker and reload once the verdict is cached.
function wlCheckVt(domain) {
    fetch('/ajax_vt_request.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': wlCsrf()},
        body: JSON.stringify({domain: domain, force: true})
    })
    .then(r => r.json())
    .then(function (res) {
        if (!res.success) throw new Error(res.error || 'request failed');
        if (!res.queued) { window.location.reload(); return; }
        wlPollVt(domain, 0);
    })
    .catch(function (e) { alert('VirusTotal request failed: ' + e.message); });
}
function wlPollVt(domain, tries) {
    if (tries > 40) { alert('Timed out waiting for the worker.'); return; }
    fetch('/ajax_vt_cache.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(function (data) {
            if (data && data.success && data.vt) { window.location.reload(); return; }
            setTimeout(function () { wlPollVt(domain, tries + 1); }, 5000);
        })
        .catch(function () { setTimeout(function () { wlPollVt(domain, tries + 1); }, 6000); });
}
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
