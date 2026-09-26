// Intelligence tracking actions (check / clear / extend / delete).
// Uses the themed App.toast / App.confirm / App.prompt components.
(function () {
    'use strict';

    function csrf() {
        if (window.App && App.csrf) return App.csrf();
        return (typeof window.csrfToken === 'function') ? window.csrfToken() : '';
    }

    function toast(message, type, opts) {
        if (window.App && App.toast) { App.toast(message, type, opts); }
        else { window.alert(message); }
    }

    function confirmDialog(opts) {
        if (window.App && App.confirm) return App.confirm(opts);
        return Promise.resolve(window.confirm(opts.message || ''));
    }

    function promptDialog(opts) {
        if (window.App && App.prompt) return App.prompt(opts);
        return Promise.resolve(window.prompt(opts.message || '', opts.value || ''));
    }

    function post(payload) {
        return fetch('/ajax_tracking.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
            body: JSON.stringify(payload)
        }).then(function (r) { return r.json(); });
    }

    function cancelCommand(commandId) {
        fetch('/ajax_command_cancel.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
            body: JSON.stringify({ command_id: commandId })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.success) { toast('Queued check cancelled.', 'success'); }
                else { toast(data.error || 'Could not cancel the check.', 'error'); }
            })
            .catch(function () { toast('Could not cancel the check.', 'error'); });
    }

    function queuedToast(res, message) {
        var opts = { title: 'Queued' };
        if (res && res.command_id) {
            opts.actionLabel = 'Cancelar';
            opts.onAction = function () { cancelCommand(res.command_id); };
        }
        toast(message, 'success', opts);
    }

    window.intelCheck = function (id, domain) {
        confirmDialog({
            title: 'Queue Intelligence check',
            message: domain ? ('Check ' + domain + ' now?') : 'Check this domain now?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            post({ action: 'check', domains: domain ? [domain] : null })
                .then(function (res) {
                    if (res.success) { queuedToast(res, 'Check queued. The worker will validate it shortly.'); }
                    else { toast(res.error || 'Failed to queue the check', 'error'); }
                })
                .catch(function () { toast('Failed to queue the check', 'error'); });
        });
    };

    window.intelCheckAll = function () {
        confirmDialog({
            title: 'Queue Intelligence check',
            message: 'Check all due tracked domains now?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            post({ action: 'check' })
                .then(function (res) {
                    if (res.success) { queuedToast(res, 'Check queued for all due tracked domains.'); }
                    else { toast(res.error || 'Failed to queue the check', 'error'); }
                })
                .catch(function () { toast('Failed to queue the check', 'error'); });
        });
    };

    window.intelClear = function (id) {
        confirmDialog({
            title: 'Stop tracking',
            message: 'Stop tracking and mark this domain as dormant?',
            confirmText: 'Aceptar'
        }).then(function (ok) {
            if (!ok) return;
            post({ action: 'clear', id: id }).then(function (res) {
                if (res.success) { location.reload(); } else { toast(res.error || 'Failed', 'error'); }
            });
        });
    };

    window.intelExtend = function (id) {
        promptDialog({
            title: 'Extend tracking',
            message: 'Extend the tracking window by how many days?',
            value: '90',
            type: 'number',
            confirmText: 'Aceptar'
        }).then(function (d) {
            if (d === null) return;
            var days = parseInt(d, 10);
            if (!days || days < 1) { toast('Enter a valid number of days.', 'warning'); return; }
            post({ action: 'extend', id: id, days: days }).then(function (res) {
                if (res.success) { location.reload(); } else { toast(res.error || 'Failed', 'error'); }
            });
        });
    };

    window.intelDelete = function (id) {
        confirmDialog({
            title: 'Delete tracking row',
            message: 'Delete this tracking row? This cannot be undone.',
            confirmText: 'Delete',
            danger: true
        }).then(function (ok) {
            if (!ok) return;
            post({ action: 'delete', id: id }).then(function (res) {
                if (res.success) { location.reload(); } else { toast(res.error || 'Failed', 'error'); }
            });
        });
    };
})();
