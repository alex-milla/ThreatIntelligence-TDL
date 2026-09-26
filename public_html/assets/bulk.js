// Shared bulk WHOIS / VirusTotal / abuse.ch / Cloudflare actions for the list
// pages. Domains are collected from rows carrying [data-domain]. If any row
// checkbox (.row-check) is checked, only those are used; otherwise every visible
// row on the page. The lookups are executed by the worker; the web only queues
// them. Messages use the themed App.toast / App.confirm components.
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

    // Undo a just-queued command while it is still pending on the worker.
    function cancelCommand(commandId) {
        fetch('/ajax_command_cancel.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ command_id: commandId })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) { toast('Queued command cancelled.', 'success'); }
                else { toast(data.error || 'Could not cancel the command.', 'error'); }
            })
            .catch(function () { toast('Could not cancel the command.', 'error'); });
    }

    // Shared handling of a queue endpoint response: use the server's own count
    // and message, and offer "Cancelar" when something was actually queued.
    function handleQueueResponse(data, label, requested) {
        if (!data || !data.success) {
            toast((data && data.error) || ('Failed to queue ' + label), 'error');
            return;
        }
        var queued = data.queued || 0;
        if (queued <= 0) {
            toast(data.message || ('Nothing to queue for ' + label + '.'), 'warning');
            return;
        }
        var msg = 'Queued ' + queued + ' domain(s) for ' + label + '.';
        if (requested && queued < requested) {
            msg += ' ' + (requested - queued) + ' skipped (already cached or queued).';
        }
        if (data.command_id) {
            toast(msg, 'success', {
                title: 'Queued',
                actionLabel: 'Cancelar',
                onAction: function () { cancelCommand(data.command_id); }
            });
        } else {
            toast(msg, 'success');
        }
    }

    // Domains to act on: the checked rows if any, otherwise every visible row.
    // Excluded rows (data-excluded="1") are skipped for WHOIS/VT unless
    // includeExcluded is true (needed by the bulk unexclude action).
    function collectDomains(includeExcluded) {
        var all = [];
        var checked = [];
        document.querySelectorAll('tr[data-domain]').forEach(function (tr) {
            var domain = tr.getAttribute('data-domain');
            if (!domain) return;
            if (!includeExcluded && tr.getAttribute('data-excluded') === '1') return;
            all.push(domain);
            var cb = tr.querySelector('.row-check');
            if (cb && cb.checked) checked.push(domain);
        });
        return checked.length ? checked : all;
    }

    function selectedDomains() {
        return collectDomains(false);
    }

    // Only the explicitly checked rows (used by the bulk tag action so it can
    // never mass-edit every visible domain by accident).
    function checkedDomains(includeExcluded) {
        var checked = [];
        document.querySelectorAll('tr[data-domain] .row-check:checked').forEach(function (cb) {
            var tr = cb.closest ? cb.closest('tr[data-domain]') : null;
            if (!tr) return;
            if (!includeExcluded && tr.getAttribute('data-excluded') === '1') return;
            var domain = tr.getAttribute('data-domain');
            if (domain) checked.push(domain);
        });
        return checked;
    }

    window.fetchVisibleWhois = function () {
        // If rows are explicitly checked, force a refresh of exactly those
        // domains (re-queue even if already cached). With no explicit selection,
        // fill in the missing WHOIS for every visible row (no forced refresh).
        var checked = checkedDomains(false);
        var explicit = checked.length > 0;
        var domains = explicit ? checked : selectedDomains();
        if (!domains.length) { toast('No domains to fetch.', 'warning'); return; }
        confirmDialog({
            title: 'Queue WHOIS lookup',
            message: (explicit ? 'Force a WHOIS refresh for ' : 'Fetch WHOIS for ')
                + domains.length + ' domain(s)?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            var payload = { domains: domains };
            if (explicit) { payload.force = true; }
            fetch('/ajax_whois_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify(payload)
            })
                .then(function (r) { return r.json(); })
                .then(function (data) { handleQueueResponse(data, 'WHOIS', domains.length); })
                .catch(function () { toast('Failed to queue WHOIS lookup', 'error'); });
        });
    };

    window.fetchVisibleVt = function () {
        var domains = selectedDomains();
        if (!domains.length) { toast('No domains to check.', 'warning'); return; }
        confirmDialog({
            title: 'Queue VirusTotal lookup',
            message: 'Check ' + domains.length + ' domain(s) with VirusTotal? The free API allows 4 requests/min and 500/day.',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_vt_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domains: domains })
            })
                .then(function (r) { return r.json(); })
                .then(function (data) { handleQueueResponse(data, 'VirusTotal', domains.length); })
                .catch(function () { toast('Failed to queue VirusTotal lookup', 'error'); });
        });
    };

    window.fetchVisibleAbusech = function () {
        var domains = selectedDomains();
        if (!domains.length) { toast('No domains to check.', 'warning'); return; }
        confirmDialog({
            title: 'Queue abuse.ch lookup',
            message: 'Check ' + domains.length + ' domain(s) with abuse.ch (URLhaus + ThreatFox)?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_abusech_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domains: domains })
            })
                .then(function (r) { return r.json(); })
                .then(function (data) { handleQueueResponse(data, 'abuse.ch', domains.length); })
                .catch(function () { toast('Failed to queue abuse.ch lookup', 'error'); });
        });
    };

    window.fetchVisibleCfscan = function () {
        var domains = selectedDomains();
        if (!domains.length) { toast('No domains to scan.', 'warning'); return; }
        // "Force re-scan" (optional checkbox) also re-queues domains with a good
        // cached scan; without it only uncached/error/DNS-only domains are sent.
        var forceEl = document.getElementById('cf-force');
        var force = !!(forceEl && forceEl.checked);
        confirmDialog({
            title: force ? 'Force Cloudflare re-scan' : 'Queue Cloudflare scan',
            message: (force ? 'Force re-scan ' : 'Scan ') + domains.length + ' domain(s) with Cloudflare Radar? '
                + 'Scans are rate limited (~1 every 10 s) and consume the plan quota.',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            var body = { domains: domains, mode: 'scan' };
            if (force) { body.force = true; }
            fetch('/ajax_cfscan_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify(body)
            })
                .then(function (r) { return r.json(); })
                .then(function (data) { handleQueueResponse(data, 'Cloudflare Radar', domains.length); })
                .catch(function () { toast('Failed to queue Cloudflare scan', 'error'); });
        });
    };

    window.fetchVisibleCfdns = function () {
        var domains = selectedDomains();
        if (!domains.length) { toast('No domains to check.', 'warning'); return; }
        confirmDialog({
            title: 'Queue Cloudflare DNS',
            message: 'Fetch the Cloudflare DNS distribution for ' + domains.length + ' domain(s)?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_cfscan_request.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domains: domains, mode: 'dns' })
            })
                .then(function (r) { return r.json(); })
                .then(function (data) { handleQueueResponse(data, 'Cloudflare DNS', domains.length); })
                .catch(function () { toast('Failed to queue Cloudflare DNS', 'error'); });
        });
    };

    // Admin: delete the cached enrichment (WHOIS/VT/abuse.ch/Cloudflare) of the
    // selected/visible domains so the checks can be run again. Analyst data
    // (tags, watchlist, reports, Intelligence) is kept.
    window.deleteVisibleCache = function () {
        var domains = selectedDomains();
        if (!domains.length) { toast('No domains selected.', 'warning'); return; }
        confirmDialog({
            title: 'Delete cached data',
            danger: true,
            confirmText: 'Delete',
            message: 'Delete the cached data for ' + domains.length + ' domain(s)? '
                + 'Only the cached WHOIS / VirusTotal / abuse.ch / Cloudflare results are removed; '
                + 'tags, watchlist, reports and Intelligence are kept.'
        }).then(function (ok) {
            if (!ok) return;
            fetch('/ajax_domain_detail_delete.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify({ domains: domains })
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.success) { location.reload(); }
                    else { toast(data.error || 'Delete failed', 'error'); }
                })
                .catch(function () { toast('Delete failed', 'error'); });
        });
    };

    // Bulk exclude / unexclude for the per-keyword match list. An empty tag
    // clears the classification (restore). Excluded rows are included so they
    // can be restored.
    window.tagSelectedDomains = function (tag) {
        var domains = checkedDomains(true);
        if (!domains.length) { toast('Select one or more domains first.', 'warning'); return; }
        var verb = tag === '' ? 'Restore' : 'Exclude';
        confirmDialog({
            title: verb + ' domains',
            danger: tag !== '',
            confirmText: verb,
            message: verb + ' ' + domains.length + ' domain(s)?'
        }).then(function (ok) {
            if (!ok) return;
            Promise.all(domains.map(function (d) {
                return fetch('/ajax_tag_domain.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: d, tag: tag })
                }).then(function (r) { return r.json(); });
            })).then(function () {
                location.reload();
            }).catch(function () {
                toast('Some domains could not be updated.', 'error');
                location.reload();
            });
        });
    };

    // Add / remove the checked domains from the manual report queue.
    function postReportQueue(domains, queued) {
        return fetch('/ajax_report_queue.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domains: domains, queued: queued })
        }).then(function (r) { return r.json(); });
    }

    window.sendSelectedToReport = function () {
        var domains = checkedDomains(false);
        if (!domains.length) { toast('Select one or more domains first.', 'warning'); return; }
        var payload = { domains: domains, queued: true };
        // keyword_matches offers a group selector; elsewhere the group is derived
        // from the keyword(s) that matched each domain.
        var sel = document.getElementById('report-group');
        if (sel) { payload.group_key = sel.value; }
        fetch('/ajax_report_queue.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify(payload)
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) { location.reload(); }
                else { toast(data.error || 'Failed to queue domains', 'error'); }
            })
            .catch(function () { toast('Failed to queue domains', 'error'); });
    };

    window.removeSelectedFromReport = function () {
        var domains = checkedDomains(true);
        if (!domains.length) { toast('Select one or more domains first.', 'warning'); return; }
        postReportQueue(domains, false)
            .then(function (data) {
                if (data.success) { location.reload(); }
                else { toast(data.error || 'Failed to update the report queue', 'error'); }
            })
            .catch(function () { toast('Failed to update the report queue', 'error'); });
    };

    // "Select all visible" helper shared by the list pages. Delegated so it also
    // works if the table is replaced by a live refresh.
    document.addEventListener('change', function (e) {
        if (e.target && e.target.id === 'select-all') {
            document.querySelectorAll('.row-check').forEach(function (cb) {
                cb.checked = e.target.checked;
            });
        }
    });
})();
