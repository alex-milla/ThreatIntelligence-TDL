// Copy an IOC list (TXT) to the clipboard. Uses the themed App.toast.
(function () {
    'use strict';

    function toast(message, type) {
        if (window.App && App.toast) { App.toast(message, type); }
        else { window.alert(message); }
    }

    document.addEventListener('click', function (e) {
        var el = e.target.closest ? e.target.closest('[data-ioc-copy]') : null;
        if (!el) return;
        e.preventDefault();
        var url = el.getAttribute('data-url');
        fetch(url, { credentials: 'same-origin' })
            .then(function (r) { return r.text(); })
            .then(function (text) {
                var n = text.trim() ? text.trim().split('\n').filter(Boolean).length : 0;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function () {
                        toast('Copied ' + n + ' domain(s).', 'success');
                    });
                } else {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    document.body.appendChild(ta);
                    ta.select();
                    try { document.execCommand('copy'); } catch (err) {}
                    document.body.removeChild(ta);
                    toast('Copied ' + n + ' domain(s).', 'success');
                }
            })
            .catch(function () { toast('Copy failed.', 'error'); });
    });
})();
