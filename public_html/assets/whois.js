// Shared WHOIS modal logic. The lookup itself is executed by the worker; the
// web only enqueues a command and polls for the result. Requires the element ids
// used by the domain modal (modal-whois-*, modal-creation, modal-registrar, ...).
(function () {
    'use strict';

    function csrfToken() {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }

    function currentDomain() {
        try {
            return (typeof _modalDomain !== 'undefined' && _modalDomain) ? _modalDomain : '';
        } catch (e) {
            return '';
        }
    }

    function escapeHtml(str) {
        var d = document.createElement('div');
        d.textContent = str == null ? '' : String(str);
        return d.innerHTML;
    }

    function fmtDate(s) {
        if (!s) return 'N/A';
        var d;
        if (/^\d+$/.test(String(s))) {
            d = new Date(parseInt(s, 10) * 1000); // unix seconds
        } else {
            d = new Date(s);
        }
        return isNaN(d.getTime()) ? s : d.toLocaleString();
    }

    function renderFirstSeen(fs) {
        var el = document.getElementById('modal-first-seen');
        if (!el) return;
        el.textContent = fs ? fmtDate(fs) : 'N/A';
    }

    function setButton(text) {
        var b = document.getElementById('modal-whois-btn');
        if (b) {
            b.textContent = text;
            b.style.display = 'block';
        }
    }

    function renderStatus(w) {
        var el = document.getElementById('modal-whois-status');
        if (!el) return;
        var status = w && w.status ? w.status : '';
        if (status === 'unsupported') {
            el.textContent = 'This registry does not publish WHOIS/RDAP data (e.g. .es). '
                + 'Using the first time the domain was seen in zone data.';
            el.style.display = 'block';
        } else if (status === 'error') {
            el.textContent = 'WHOIS lookup failed (registry blocked or unreachable). You can retry.';
            el.style.display = 'block';
        } else {
            el.style.display = 'none';
        }
    }

    function renderEmptyWhois() {
        ['modal-creation', 'modal-expiration', 'modal-registrar', 'modal-ns'].forEach(function (id) {
            var e = document.getElementById(id);
            if (e) e.textContent = 'N/A';
        });
        var st = document.getElementById('modal-whois-status');
        if (st) st.style.display = 'none';
        var err = document.getElementById('modal-whois-error');
        if (err) err.style.display = 'none';
    }

    function renderWhois(w) {
        document.getElementById('modal-creation').textContent = fmtDate(w.creation_date);
        document.getElementById('modal-expiration').textContent = fmtDate(w.expiration_date);
        document.getElementById('modal-registrar').textContent = w.registrar || 'N/A';
        var ns = w.name_servers || [];
        document.getElementById('modal-ns').innerHTML = ns.length
            ? ns.map(function (n) { return '<div>' + escapeHtml(n) + '</div>'; }).join('')
            : 'N/A';
        document.getElementById('modal-whois-loading').style.display = 'none';
        document.getElementById('modal-whois-content').style.display = 'block';
        document.getElementById('modal-whois-error').style.display = 'none';
        renderFirstSeen(w.first_seen);
        renderStatus(w);
        setButton('\uD83D\uDD04 Refresh WHOIS');
    }

    window.loadCachedWhois = function () {
        var domain = currentDomain();
        if (!domain) return;
        document.getElementById('modal-whois-loading').style.display = 'none';
        document.getElementById('modal-whois-content').style.display = 'none';
        document.getElementById('modal-whois-error').style.display = 'none';
        fetch('/ajax_whois_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderFirstSeen(data ? data.first_seen : null);
                if (data.success && data.whois) {
                    renderWhois(data.whois);
                } else {
                    renderEmptyWhois();
                    setButton('\uD83D\uDD0D Fetch WHOIS (worker)');
                }
            })
            .catch(function () { setButton('\uD83D\uDD0D Fetch WHOIS (worker)'); });
    };

    window.fetchWhois = function () {
        var domain = currentDomain();
        if (!domain) return;
        var loading = document.getElementById('modal-whois-loading');
        var err = document.getElementById('modal-whois-error');
        document.getElementById('modal-whois-btn').style.display = 'none';
        if (err) err.style.display = 'none';
        if (loading) loading.style.display = 'block';

        fetch('/ajax_whois_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domain: domain, force: true })
        })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (!res.success) throw new Error(res.error || 'request failed');
                pollWhois(res.command_id, domain, 0);
            })
            .catch(function (e) {
                if (loading) loading.style.display = 'none';
                if (err) { err.textContent = 'WHOIS request failed: ' + e.message; err.style.display = 'block'; }
                setButton('\uD83D\uDD0D Fetch WHOIS (worker)');
            });
    };

    function pollWhois(commandId, domain, tries) {
        if (tries > 45) { // ~3 min
            var loading = document.getElementById('modal-whois-loading');
            var err = document.getElementById('modal-whois-error');
            if (loading) loading.style.display = 'none';
            if (err) { err.textContent = 'Timed out waiting for the worker.'; err.style.display = 'block'; }
            setButton('\uD83D\uDD0D Fetch WHOIS (worker)');
            return;
        }
        fetch('/ajax_whois_result.php?command_id=' + encodeURIComponent(commandId || '') +
              '&domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.whois) {
                    renderWhois(data.whois);
                    return;
                }
                if (data.command_status === 'failed' || data.command_status === 'cancelled') {
                    var loading = document.getElementById('modal-whois-loading');
                    var err = document.getElementById('modal-whois-error');
                    if (loading) loading.style.display = 'none';
                    if (err) { err.textContent = 'Worker could not fetch WHOIS (' + data.command_status + ').'; err.style.display = 'block'; }
                    setButton('\uD83D\uDD0D Fetch WHOIS (worker)');
                    return;
                }
                setTimeout(function () { pollWhois(commandId, domain, tries + 1); }, 4000);
            })
            .catch(function () { setTimeout(function () { pollWhois(commandId, domain, tries + 1); }, 6000); });
    }
})();
