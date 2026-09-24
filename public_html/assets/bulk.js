// Shared bulk WHOIS / VirusTotal actions for the list pages.
// Domains are collected from rows carrying [data-domain]. If any row checkbox
// (.row-check) is checked, only those are used; otherwise every visible row on
// the page. The lookups are executed by the worker; the web only queues them.
(function () {
    'use strict';

    function csrfToken() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
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
        if (!domains.length) { alert('No domains to fetch.'); return; }
        var payload = { domains: domains };
        if (explicit) { payload.force = true; }
        fetch('/ajax_whois_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify(payload)
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) {
                    alert('Queued ' + (data.queued || 0) + ' domain(s) for the worker. Reload in a moment to see results.');
                } else {
                    alert(data.error || 'Failed to queue WHOIS lookup');
                }
            })
            .catch(function () { alert('Failed to queue WHOIS lookup'); });
    };

    window.fetchVisibleVt = function () {
        var domains = selectedDomains();
        if (!domains.length) { alert('No domains to check.'); return; }
        fetch('/ajax_vt_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domains: domains })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) {
                    alert('Queued ' + (data.queued || 0) + ' domain(s) for VirusTotal. The free API allows 4 requests/min and 500/day; reload in a moment to see verdicts.');
                } else {
                    alert(data.error || 'Failed to queue VirusTotal lookup');
                }
            })
            .catch(function () { alert('Failed to queue VirusTotal lookup'); });
    };

    window.fetchVisibleAbusech = function () {
        var domains = selectedDomains();
        if (!domains.length) { alert('No domains to check.'); return; }
        fetch('/ajax_abusech_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domains: domains })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) {
                    alert('Queued ' + (data.queued || 0) + ' domain(s) for abuse.ch (URLhaus + ThreatFox). Reload in a moment to see results.');
                } else {
                    alert(data.error || 'Failed to queue abuse.ch lookup');
                }
            })
            .catch(function () { alert('Failed to queue abuse.ch lookup'); });
    };

    // Bulk exclude / unexclude for the per-keyword match list. An empty tag
    // clears the classification (restore). Excluded rows are included so they
    // can be restored.
    window.tagSelectedDomains = function (tag) {
        var domains = checkedDomains(true);
        if (!domains.length) { alert('Select one or more domains first.'); return; }
        var verb = tag === '' ? 'Restore' : 'Exclude';
        if (!confirm(verb + ' ' + domains.length + ' domain(s)?')) return;
        Promise.all(domains.map(function (d) {
            return fetch('/ajax_tag_domain.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: d, tag: tag })
            }).then(function (r) { return r.json(); });
        })).then(function () {
            location.reload();
        }).catch(function () {
            alert('Some domains could not be updated.');
            location.reload();
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
        if (!domains.length) { alert('Select one or more domains first.'); return; }
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
                else { alert(data.error || 'Failed to queue domains'); }
            })
            .catch(function () { alert('Failed to queue domains'); });
    };

    window.removeSelectedFromReport = function () {
        var domains = checkedDomains(true);
        if (!domains.length) { alert('Select one or more domains first.'); return; }
        postReportQueue(domains, false)
            .then(function (data) {
                if (data.success) { location.reload(); }
                else { alert(data.error || 'Failed to update the report queue'); }
            })
            .catch(function () { alert('Failed to update the report queue'); });
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
