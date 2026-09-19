// Shared VirusTotal panel logic (mirrors assets/whois.js). Uses the domain
// modal element ids: modal-vt-verdict, modal-vt-error, and the global _modalDomain.
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

    function escapeHtml(s) {
        var d = document.createElement('div');
        d.textContent = s == null ? '' : String(s);
        return d.innerHTML;
    }

    function verdictLabel(v) {
        switch (v) {
            case 'malicious': return 'MALICIOUS';
            case 'dga': return 'DGA';
            case 'suspicious': return 'SUSPICIOUS';
            case 'clean': return 'CLEAN';
            default: return 'UNKNOWN';
        }
    }

    function render(v) {
        var box = document.getElementById('modal-vt-verdict');
        if (!box) return;
        if (!v) {
            box.innerHTML = '<span class="muted">Not checked yet</span>';
            return;
        }
        var vd = v.verdict || 'unknown';
        var html = '<span class="vt-badge vt-' + escapeHtml(vd) + '">' + verdictLabel(vd) + '</span>';
        html += ' <span class="muted">' + (v.malicious | 0) + ' malicious / ' + (v.suspicious | 0) + ' suspicious</span>';
        if (v.tags) {
            html += '<div class="muted" style="font-size:.78rem;">' + escapeHtml(v.tags) + '</div>';
        }
        box.innerHTML = html;
    }

    window.loadVtStatus = function () {
        var domain = currentDomain();
        if (!domain) return;
        var box = document.getElementById('modal-vt-verdict');
        if (box) box.textContent = 'Loading...';
        fetch('/ajax_vt_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) { render(data && data.success ? data.vt : null); })
            .catch(function () { render(null); });
    };

    window.checkVt = function () {
        var domain = currentDomain();
        if (!domain) return;
        var box = document.getElementById('modal-vt-verdict');
        var err = document.getElementById('modal-vt-error');
        if (err) err.style.display = 'none';
        if (box) box.textContent = 'Queued; waiting for the worker (free API = 4/min)...';
        fetch('/ajax_vt_request.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify({ domain: domain, force: true })
        })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (!res.success) throw new Error(res.error || 'request failed');
                if (!res.queued) { window.loadVtStatus(); return; }
                pollVt(domain, 0);
            })
            .catch(function (e) {
                if (err) { err.textContent = 'VirusTotal request failed: ' + e.message; err.style.display = 'block'; }
                if (box) box.textContent = 'Not checked yet';
            });
    };

    function pollVt(domain, tries) {
        if (tries > 40) {
            var err = document.getElementById('modal-vt-error');
            if (err) { err.textContent = 'Timed out waiting for the worker.'; err.style.display = 'block'; }
            return;
        }
        fetch('/ajax_vt_cache.php?domain=' + encodeURIComponent(domain))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.success && data.vt) { render(data.vt); return; }
                setTimeout(function () { pollVt(domain, tries + 1); }, 5000);
            })
            .catch(function () { setTimeout(function () { pollVt(domain, tries + 1); }, 6000); });
    }
})();
