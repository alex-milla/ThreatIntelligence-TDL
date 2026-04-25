<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
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

// Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 50;

// Count
$totalStmt = $db->prepare("SELECT COUNT(*) FROM watchlist WHERE user_id = ?");
$totalStmt->execute([$userId]);
$total = (int)$totalStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
$page = min($page, $totalPages);
$offset = ($page - 1) * $perPage;

// Fetch
$stmt = $db->prepare("SELECT id, domain, note, created_at FROM watchlist WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?");
$stmt->execute([$userId, $perPage, $offset]);
$items = $stmt->fetchAll();

// Load whois for visible rows
$domainWhois = [];
if (!empty($items)) {
    $domains = array_column($items, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $whoisStmt = $db->prepare("SELECT domain, creation_date FROM domain_whois WHERE domain IN ($placeholders)");
    $whoisStmt->execute($domains);
    foreach ($whoisStmt->fetchAll() as $w) {
        $domainWhois[$w['domain']] = $w;
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

$pageTitle = 'Watchlist';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <h2>⭐ Watchlist</h2>
    <p style="color: #666; font-size: 0.9rem;">Private list of domains you are tracking for monitoring over time. Notes are personal and not shared with other users.</p>

    <?php if (empty($items)): ?>
        <p>Your watchlist is empty. Add domains from the <a href="/notifications.php">Notifications</a> page or from any domain modal.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Created</th>
                    <th>Note</th>
                    <th>Added</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($items as $item):
                    $whois = $domainWhois[$item['domain']] ?? null;
                    $creationDate = $whois['creation_date'] ?? null;
                    $creationDisplay = $creationDate ? date('Y-m-d', strtotime($creationDate)) : '—';
                    $dtag = $domainTags[$item['domain']] ?? null;
                    $tagBadge = '';
                    if ($dtag) {
                        $color = $dtag['tag'] === 'good' ? '#27ae60' : '#c0392b';
                        $label = $dtag['tag'] === 'good' ? 'GOOD' : 'BAD';
                        $tagBadge = ' <span style="display:inline-block;background:'.$color.';color:#fff;font-size:0.7rem;padding:1px 5px;border-radius:3px;margin-left:4px;">'.$label.'</span>';
                    }
                ?>
                <tr>
                    <td>
                        <a href="javascript:void(0)" onclick="openDomainModal('<?= htmlspecialchars(addslashes($item['domain'])) ?>')" style="color: #3498db; text-decoration: underline; cursor: pointer;"><?= htmlspecialchars($item['domain']) ?></a><?= $tagBadge ?>
                    </td>
                    <td><?= htmlspecialchars($creationDisplay) ?></td>
                    <td>
                        <form method="POST" style="margin: 0; display: flex; gap: 6px; align-items: center;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="update_note">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <input type="text" name="note" value="<?= htmlspecialchars($item['note'] ?? '') ?>" placeholder="Add a note..." style="flex: 1; min-width: 120px; padding: 6px; font-size: 0.9rem;">
                            <button type="submit" class="btn btn-small">Save</button>
                        </form>
                    </td>
                    <td><?= htmlspecialchars($item['created_at']) ?></td>
                    <td>
                        <form method="POST" style="margin: 0;" onsubmit="return confirm('Remove this domain from your watchlist?')">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="remove">
                            <input type="hidden" name="watch_id" value="<?= (int)$item['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger">Remove</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <span style="color: #666; font-size: 0.9rem;">
                Showing <?= (($page - 1) * $perPage + 1) ?> - <?= min($page * $perPage, $total) ?> of <?= $total ?> domains
            </span>
            <div style="display: flex; gap: 5px; flex-wrap: wrap;">
                <?php if ($page > 1): ?>
                    <a href="/watchlist.php?page=<?= $page - 1 ?>" class="btn btn-small">« Previous</a>
                <?php endif; ?>

                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <?php if ($p === $page): ?>
                        <span class="btn btn-small" style="background: #3498db; color: white; cursor: default;"><?= $p ?></span>
                    <?php elseif ($p === 1 || $p === $totalPages || abs($p - $page) <= 2): ?>
                        <a href="/watchlist.php?page=<?= $p ?>" class="btn btn-small"><?= $p ?></a>
                    <?php elseif (abs($p - $page) === 3): ?>
                        <span style="padding: 5px;">…</span>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="/watchlist.php?page=<?= $page + 1 ?>" class="btn btn-small">Next »</a>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
</div>

<!-- Domain detail modal -->
<div id="domain-modal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center;">
    <div style="background: white; padding: 25px; border-radius: 8px; max-width: 520px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-height: 90vh; overflow-y: auto;">
        <h3 id="modal-domain-title" style="margin-top: 0; word-break: break-all;"></h3>
        <div id="modal-whois-box" style="margin: 15px 0;">
            <button type="button" id="modal-whois-btn" class="btn" style="width: 100%;" onclick="fetchWhois()">🔍 Consultar Whois (RDAP)</button>
            <div id="modal-whois-loading" style="display: none; color: #666; font-size: 0.9rem; margin-top: 10px;">Consultando whois...</div>
            <div id="modal-whois-content" style="display: none; margin-top: 10px;">
                <table style="width: 100%; font-size: 0.9rem;">
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Creation Date</td><td id="modal-creation" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Expiration Date</td><td id="modal-expiration" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Registrar</td><td id="modal-registrar" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0; vertical-align: top;">Name Servers</td><td id="modal-ns" style="font-weight: 600;"></td></tr>
                </table>
            </div>
            <div id="modal-whois-error" style="display: none; color: #c0392b; font-size: 0.9rem; margin-top: 10px;"></div>
        </div>
        <div id="modal-watchlist-box" style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 4px; display: none;">
            <div style="font-size: 0.85rem; color: #666; margin-bottom: 6px;">Watchlist</div>
            <div id="modal-watchlist-current" style="font-weight: 600; margin-bottom: 8px;"></div>
            <div id="modal-watchlist-actions" style="display: flex; gap: 8px;">
                <button type="button" id="modal-watchlist-btn" class="btn btn-small" style="flex:1;" onclick="toggleWatchlist(_modalDomain)">⭐ Add to Watchlist</button>
            </div>
        </div>
        <div id="modal-tag-box" style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 4px; display: none;">
            <div style="font-size: 0.85rem; color: #666; margin-bottom: 6px;">Domain classification</div>
            <div id="modal-tag-current" style="font-weight: 600; margin-bottom: 8px;"></div>
            <div style="display: flex; gap: 8px;">
                <button type="button" class="btn btn-small" style="background:#27ae60; flex:1;" onclick="tagDomain(_modalDomain, 'good')">Mark Good</button>
                <button type="button" class="btn btn-small" style="background:#c0392b; flex:1;" onclick="tagDomain(_modalDomain, 'bad')">Mark Bad</button>
                <button type="button" class="btn btn-small btn-danger" style="flex:1;" onclick="tagDomain(_modalDomain, '')">Remove</button>
            </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 15px;">
            <a id="modal-vt" href="#" target="_blank" class="btn" style="text-align: center; background: #3949ab;">🛡️ Open in VirusTotal</a>
        </div>
        <button onclick="document.getElementById('domain-modal').style.display='none'" class="btn btn-danger" style="margin-top: 15px; width: 100%;">Close</button>
    </div>
</div>

<script>
let _modalDomain = '';
function openDomainModal(domain) {
    _modalDomain = domain;
    document.getElementById('modal-domain-title').textContent = domain;
    document.getElementById('modal-vt').href = 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain);
    document.getElementById('modal-whois-btn').style.display = 'block';
    document.getElementById('modal-whois-loading').style.display = 'none';
    document.getElementById('modal-whois-content').style.display = 'none';
    document.getElementById('modal-whois-error').style.display = 'none';
    document.getElementById('modal-tag-box').style.display = 'block';
    document.getElementById('modal-tag-current').textContent = 'Loading...';
    document.getElementById('modal-watchlist-box').style.display = 'block';
    document.getElementById('modal-watchlist-current').textContent = 'Loading...';
    document.getElementById('domain-modal').style.display = 'flex';
    loadDomainTag(domain);
    loadWatchlistStatus(domain);
}
function loadDomainTag(domain) {
    fetch('/ajax_tag_domain.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-tag-current');
            if (data.success && data.tag) {
                const color = data.tag.tag === 'good' ? '#27ae60' : '#c0392b';
                box.innerHTML = '<span style="color:' + color + '; font-weight:700;">' + data.tag.tag.toUpperCase() + '</span>';
                if (data.tag.note) box.innerHTML += ' — ' + htmlspecialchars(data.tag.note);
            } else {
                box.textContent = 'Not classified';
            }
        })
        .catch(() => {
            document.getElementById('modal-tag-current').textContent = 'Unable to load tag';
        });
}
function loadWatchlistStatus(domain) {
    fetch('/ajax_watchlist.php?check=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-watchlist-current');
            const btn = document.getElementById('modal-watchlist-btn');
            if (data.in_watchlist) {
                box.innerHTML = '<span style="color: #f39c12;">⭐ In watchlist</span>' + (data.note ? ' — ' + htmlspecialchars(data.note) : '');
                btn.textContent = 'Remove from Watchlist';
                btn.style.background = '#e74c3c';
            } else {
                box.textContent = 'Not in watchlist';
                btn.textContent = '⭐ Add to Watchlist';
                btn.style.background = '';
            }
        })
        .catch(() => {
            document.getElementById('modal-watchlist-current').textContent = 'Unable to load watchlist status';
        });
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
            loadWatchlistStatus(domain);
            // If we're on the watchlist page, reload to reflect changes
            if (window.location.pathname === '/watchlist.php') {
                window.location.reload();
            }
        } else {
            alert(data.error || 'Failed to update watchlist');
        }
    })
    .catch(() => alert('Failed to update watchlist'));
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
            loadDomainTag(domain);
            window.location.reload();
        } else {
            alert(data.error || 'Failed to tag domain');
        }
    })
    .catch(() => alert('Failed to tag domain'));
}
function htmlspecialchars(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
function fetchWhois() {
    if (!_modalDomain) return;
    document.getElementById('modal-whois-btn').style.display = 'none';
    document.getElementById('modal-whois-loading').style.display = 'block';
    document.getElementById('modal-whois-error').style.display = 'none';

    fetch('/ajax_whois.php?domain=' + encodeURIComponent(_modalDomain))
        .then(r => r.json())
        .then(data => {
            document.getElementById('modal-whois-loading').style.display = 'none';
            if (data.success) {
                document.getElementById('modal-creation').textContent = data.creationDate ? new Date(data.creationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-expiration').textContent = data.expirationDate ? new Date(data.expirationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-registrar').textContent = data.registrar || 'N/A';
                document.getElementById('modal-ns').innerHTML = data.nameServers.length ? data.nameServers.map(ns => '<div>' + ns + '</div>').join('') : 'N/A';
                document.getElementById('modal-whois-content').style.display = 'block';
            } else {
                document.getElementById('modal-whois-error').textContent = 'Whois unavailable: ' + (data.error || 'Unknown error');
                document.getElementById('modal-whois-error').style.display = 'block';
                document.getElementById('modal-whois-btn').style.display = 'block';
            }
        })
        .catch(() => {
            document.getElementById('modal-whois-loading').style.display = 'none';
            document.getElementById('modal-whois-error').textContent = 'Whois query failed. Try again later.';
            document.getElementById('modal-whois-error').style.display = 'block';
            document.getElementById('modal-whois-btn').style.display = 'block';
        });
}
document.getElementById('domain-modal').addEventListener('click', function(e) {
    if (e.target === this) this.style.display = 'none';
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
