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

    function selectedDomains() {
        var all = [];
        var checked = [];
        document.querySelectorAll('tr[data-domain]').forEach(function (tr) {
            var domain = tr.getAttribute('data-domain');
            if (!domain) return;
            all.push(domain);
            var cb = tr.querySelector('.row-check');
            if (cb && cb.checked) checked.push(domain);
        });
        return checked.length ? checked : all;
    }

    window.fetchVisibleWhois = function () {
        var domains = selectedDomains();
        if (!domains.length) { alert('No domains to fetch.'); return; }
        fetch('/ajax_whois_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domains: domains })
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
