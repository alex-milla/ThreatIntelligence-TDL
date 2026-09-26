// Shared rich domain detail block: row toggle + action footer.
//
// The block itself is rendered server-side (see includes/domain_detail.php);
// this file wires the action buttons. Pages can override window.ddAfterAction
// to refresh in place instead of reloading (the Dashboard lookup does).
// Messages use the themed App.toast / App.confirm components.
(function () {
    'use strict';

    function csrfToken() {
        if (window.App && App.csrf) return App.csrf();
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }

    function toast(message, type, opts) {
        if (window.App && App.toast) { App.toast(message, type, opts); }
        else { window.alert(message); }
    }

    function confirmDialog(opts) {
        if (window.App && App.confirm) return App.confirm(opts);
        return Promise.resolve(window.confirm(opts.message || ''));
    }

    // Stop polling a check the user just cancelled (keyed by label + domain).
    var cancelled = {};
    function cancelCommand(commandId, label, domain) {
        fetch('/ajax_command_cancel.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ command_id: commandId })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) {
                    cancelled[label + ':' + domain] = true;
                    toast('Queued command cancelled.', 'success');
                } else {
                    toast(data.error || 'Could not cancel the command.', 'error');
                }
            })
            .catch(function () { toast('Could not cancel the command.', 'error'); });
    }

    // Success toast for a queued check, with an undo action while it is pending.
    function queuedToast(res, label, domain) {
        var opts = { title: 'Queued' };
        if (res && res.command_id) {
            opts.actionLabel = 'Cancelar';
            opts.onAction = function () { cancelCommand(res.command_id, label, domain); };
        }
        toast('Queued ' + label + ' for ' + domain + '.', 'success', opts);
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
            else { toast(d.error || 'Failed to tag domain', 'error'); }
        })
        .catch(function () { toast('Failed to tag domain', 'error'); });
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
            else { toast(d.error || 'Failed to update watchlist', 'error'); }
        })
        .catch(function () { toast('Failed to update watchlist', 'error'); });
    };

    // Queue a WHOIS refresh on the worker, then refresh once cached.
    window.ddFetchWhois = function (domain) {
        confirmDialog({
            title: 'Queue WHOIS refresh',
            message: 'Fetch WHOIS for ' + domain + '?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_whois_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain, force: true })
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (!res.success) throw new Error(res.error || 'request failed');
                    queuedToast(res, 'WHOIS', domain);
                    ddPollWhois(res.command_id, domain, 0);
                })
                .catch(function (e) { toast('WHOIS request failed: ' + e.message, 'error'); });
        });
    };

    function ddPollWhois(commandId, domain, tries) {
        if (cancelled['WHOIS:' + domain]) return;
        if (tries > 45) { toast('Timed out waiting for the worker.', 'warning'); return; }
        fetch('/ajax_whois_result.php?command_id=' + encodeURIComponent(commandId || '') + '&domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (cancelled['WHOIS:' + domain]) return;
                if (data.whois) { window.ddAfterAction(domain); return; }
                if (data.command_status === 'failed' || data.command_status === 'cancelled') {
                    toast('Worker could not fetch WHOIS (' + data.command_status + ').', 'error');
                    return;
                }
                setTimeout(function () { ddPollWhois(commandId, domain, tries + 1); }, 4000);
            })
            .catch(function () { setTimeout(function () { ddPollWhois(commandId, domain, tries + 1); }, 6000); });
    }

    // Queue a VirusTotal check on the worker, then refresh once cached.
    window.ddCheckVt = function (domain) {
        confirmDialog({
            title: 'Queue VirusTotal lookup',
            message: 'Check ' + domain + ' with VirusTotal? The free API allows 4 requests/min and 500/day.',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_vt_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain, force: true })
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (!res.success) throw new Error(res.error || 'request failed');
                    if (!res.queued) { window.ddAfterAction(domain); return; }
                    queuedToast(res, 'VirusTotal', domain);
                    ddPollVt(domain, 0);
                })
                .catch(function (e) { toast('VirusTotal request failed: ' + e.message, 'error'); });
        });
    };

    function ddPollVt(domain, tries) {
        if (cancelled['VirusTotal:' + domain]) return;
        if (tries > 40) { toast('Timed out waiting for the worker.', 'warning'); return; }
        fetch('/ajax_vt_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (cancelled['VirusTotal:' + domain]) return;
                if (data && data.success && data.vt) { window.ddAfterAction(domain); return; }
                setTimeout(function () { ddPollVt(domain, tries + 1); }, 5000);
            })
            .catch(function () { setTimeout(function () { ddPollVt(domain, tries + 1); }, 6000); });
    }

    // Queue an abuse.ch (URLhaus + ThreatFox) check, then refresh once cached.
    window.ddCheckAbusech = function (domain) {
        confirmDialog({
            title: 'Queue abuse.ch lookup',
            message: 'Check ' + domain + ' with abuse.ch (URLhaus + ThreatFox)?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_abusech_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain, force: true })
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (!res.success) throw new Error(res.error || 'request failed');
                    if (!res.queued) { window.ddAfterAction(domain); return; }
                    queuedToast(res, 'abuse.ch', domain);
                    ddPollAbusech(domain, 0);
                })
                .catch(function (e) { toast('abuse.ch request failed: ' + e.message, 'error'); });
        });
    };

    function ddPollAbusech(domain, tries) {
        if (cancelled['abuse.ch:' + domain]) return;
        if (tries > 40) { toast('Timed out waiting for the worker.', 'warning'); return; }
        fetch('/ajax_abusech_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (cancelled['abuse.ch:' + domain]) return;
                if (data && data.success && data.abusech) { window.ddAfterAction(domain); return; }
                setTimeout(function () { ddPollAbusech(domain, tries + 1); }, 5000);
            })
            .catch(function () { setTimeout(function () { ddPollAbusech(domain, tries + 1); }, 6000); });
    }

    // Queue a Cloudflare Radar URL Scanner check (scans are async and slow,
    // ~1 per 10 s on the Free plan), then refresh once cached.
    window.ddCheckCf = function (domain) {
        confirmDialog({
            title: 'Queue Cloudflare scan',
            message: 'Scan ' + domain + ' with Cloudflare Radar? Scans are rate limited (~1 every 10 s) and consume the plan quota.',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_cfscan_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain, mode: 'scan', force: true })
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (!res.success) throw new Error(res.error || 'request failed');
                    if (!res.queued) { window.ddAfterAction(domain); return; }
                    queuedToast(res, 'Cloudflare scan', domain);
                    ddPollCf(domain, 0);
                })
                .catch(function (e) { toast('Cloudflare request failed: ' + e.message, 'error'); });
        });
    };

    function ddPollCf(domain, tries) {
        // The scanner is asynchronous (~1 scan / 10 s), so be patient.
        if (cancelled['Cloudflare scan:' + domain]) return;
        if (tries > 60) { toast('Timed out waiting for the worker.', 'warning'); return; }
        fetch('/ajax_cfscan_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (cancelled['Cloudflare scan:' + domain]) return;
                if (data && data.success && data.cfscan) { window.ddAfterAction(domain); return; }
                setTimeout(function () { ddPollCf(domain, tries + 1); }, 10000);
            })
            .catch(function () { setTimeout(function () { ddPollCf(domain, tries + 1); }, 12000); });
    }

    // Queue the (cheap) Cloudflare Radar DNS top-locations lookup.
    window.ddCheckCfdns = function (domain) {
        confirmDialog({
            title: 'Queue Cloudflare DNS',
            message: 'Fetch the Cloudflare DNS distribution for ' + domain + '?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_cfscan_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain, mode: 'dns', force: true })
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (!res.success) throw new Error(res.error || 'request failed');
                    if (!res.queued) { window.ddAfterAction(domain); return; }
                    queuedToast(res, 'Cloudflare DNS', domain);
                    ddPollCfdns(domain, 0);
                })
                .catch(function (e) { toast('Cloudflare DNS request failed: ' + e.message, 'error'); });
        });
    };

    function ddPollCfdns(domain, tries) {
        if (cancelled['Cloudflare DNS:' + domain]) return;
        if (tries > 40) { toast('Timed out waiting for the worker.', 'warning'); return; }
        fetch('/ajax_cfscan_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (cancelled['Cloudflare DNS:' + domain]) return;
                var c = (data && data.success) ? data.cfscan : null;
                if (c && c.dns_countries && c.dns_countries.length) { window.ddAfterAction(domain); return; }
                setTimeout(function () { ddPollCfdns(domain, tries + 1); }, 5000);
            })
            .catch(function () { setTimeout(function () { ddPollCfdns(domain, tries + 1); }, 6000); });
    }

    // Delete the cached enrichment of this domain (WHOIS/VT/abuse.ch/Cloudflare)
    // so the checks can be run again. Admin action; analyst data is kept.
    window.ddDeleteFicha = function (domain) {
        confirmDialog({
            title: 'Delete cached data',
            danger: true,
            confirmText: 'Delete',
            message: 'Delete the cached data for ' + domain + '? This only clears the cached '
                + 'WHOIS / VirusTotal / abuse.ch / Cloudflare results so you can run the checks again. '
                + 'Tags, watchlist, reports and Intelligence are kept.'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_domain_detail_delete.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domain: domain })
            })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d.success) { window.ddAfterAction(domain); }
                    else { toast(d.error || 'Delete failed', 'error'); }
                })
                .catch(function () { toast('Delete failed', 'error'); });
        });
    };
})();
