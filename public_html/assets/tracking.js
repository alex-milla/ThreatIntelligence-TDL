(function () {
    function post(payload) {
        return fetch('/ajax_tracking.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify(payload)
        }).then(function (r) { return r.json(); });
    }

    window.intelCheck = function (id, domain) {
        post({ action: 'check', domains: domain ? [domain] : null })
            .then(function (res) {
                if (res.success) {
                    alert('Check queued. The worker will validate it shortly.');
                } else {
                    alert(res.error || 'Failed to queue the check');
                }
            })
            .catch(function () { alert('Failed to queue the check'); });
    };

    window.intelCheckAll = function () {
        post({ action: 'check' })
            .then(function (res) {
                if (res.success) {
                    alert('Check queued for all due tracked domains.');
                } else {
                    alert(res.error || 'Failed to queue the check');
                }
            })
            .catch(function () { alert('Failed to queue the check'); });
    };

    window.intelClear = function (id) {
        if (!confirm('Stop tracking and mark this domain as dormant?')) return;
        post({ action: 'clear', id: id }).then(function (res) {
            if (res.success) { location.reload(); } else { alert(res.error || 'Failed'); }
        });
    };

    window.intelExtend = function (id) {
        var d = prompt('Extend the tracking window by how many days?', '90');
        if (d === null) return;
        post({ action: 'extend', id: id, days: parseInt(d, 10) || 90 }).then(function (res) {
            if (res.success) { location.reload(); } else { alert(res.error || 'Failed'); }
        });
    };

    window.intelDelete = function (id) {
        if (!confirm('Delete this tracking row? This cannot be undone.')) return;
        post({ action: 'delete', id: id }).then(function (res) {
            if (res.success) { location.reload(); } else { alert(res.error || 'Failed'); }
        });
    };
})();
