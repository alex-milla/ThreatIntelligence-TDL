(function () {
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
                        alert('Copied ' + n + ' domain(s).');
                    });
                } else {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    document.body.appendChild(ta);
                    ta.select();
                    try { document.execCommand('copy'); } catch (err) {}
                    document.body.removeChild(ta);
                    alert('Copied ' + n + ' domain(s).');
                }
            })
            .catch(function () { alert('Copy failed.'); });
    });
})();
