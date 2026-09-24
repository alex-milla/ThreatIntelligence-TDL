// Shared rich domain detail block: row toggle + action footer.
//
// The block itself is rendered server-side (see includes/domain_detail.php);
// this file wires the action buttons. Pages can override window.ddAfterAction
// to refresh in place instead of reloading (the Dashboard lookup does).
(function () {
    'use strict';

    function csrfToken() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }

    if (typeof window.ddAfterAction !== 'function') {
        window.ddAfterAction = function () { window.location.reload(); };
    }

    // Toggle the server-rendered detail row that follows a table row.
    window.toggleDomainDetail = function (link, domain) {
        var row = link.closest('tr');
        if (!row) return;
        var detail = row.nextElementSibling;
        if (!detail || !detail.classList.contains('domain-detail-row')) return;
        if (domain && detail.getAttribute('data-domain') !== domain) return;
        var open = detail.style.display === 'none' || detail.style.display === '';
        detail.style.display = open ? 'table-row' : 'none';
        link.setAttribute('aria-expanded', open ? 'true' : 'false');
    };

    window.ddTag = function (domain, tag) {
        fetch('/ajax_tag_domain.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, tag: tag })
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d.success) { window.ddAfterAction(domain); }
            else { alert(d.error || 'Failed to tag domain'); }
        })
        .catch(function () { alert('Failed to tag domain'); });
    };

    window.ddWatchlist = function (domain) {
        fetch('/ajax_watchlist.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain })
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (d.success) { window.ddAfterAction(domain); }
            else { alert(d.error || 'Failed to update watchlist'); }
        })
        .catch(function () { alert('Failed to update watchlist'); });
    };

    // Queue a WHOIS refresh on the worker, then refresh once cached.
    window.ddFetchWhois = function (domain) {
        fetch('/ajax_whois_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domain: domain, force: true })
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (!res.success) throw new Error(res.error || 'request failed');
            ddPollWhois(res.command_id, domain, 0);
        })
        .catch(function (e) { alert('WHOIS request failed: ' + e.message); });
    };

    function ddPollWhois(commandId, domain, tries) {
        if (tries > 45) { alert('Timed out waiting for the worker.'); return; }
        fetch('/ajax_whois_result.php?command_id=' + encodeURIComponent(commandId || '') + '&domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.whois) { window.ddAfterAction(domain); return; }
                if (data.command_status === 'failed' || data.command_status === 'cancelled') {
                    alert('Worker could not fetch WHOIS (' + data.command_status + ').');
                    return;
                }
                setTimeout(function () { ddPollWhois(commandId, domain, tries + 1); }, 4000);
            })
            .catch(function () { setTimeout(function () { ddPollWhois(commandId, domain, tries + 1); }, 6000); });
    }

    // Queue a VirusTotal check on the worker, then refresh once cached.
    window.ddCheckVt = function (domain) {
        fetch('/ajax_vt_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domain: domain, force: true })
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (!res.success) throw new Error(res.error || 'request failed');
            if (!res.queued) { window.ddAfterAction(domain); return; }
            ddPollVt(domain, 0);
        })
        .catch(function (e) { alert('VirusTotal request failed: ' + e.message); });
    };

    function ddPollVt(domain, tries) {
        if (tries > 40) { alert('Timed out waiting for the worker.'); return; }
        fetch('/ajax_vt_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.success && data.vt) { window.ddAfterAction(domain); return; }
                setTimeout(function () { ddPollVt(domain, tries + 1); }, 5000);
            })
            .catch(function () { setTimeout(function () { ddPollVt(domain, tries + 1); }, 6000); });
    }
})();
