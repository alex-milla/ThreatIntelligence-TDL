/**
 * ThreatIntelligence-TDL — App JavaScript
 * Initializes Materialize components, the light/dark theme and helpers.
 * Requires materialize.min.js to be loaded first (provides global M).
 */
var App = {
    STORAGE_KEY: 'tdl-theme',

    init: function () {
        this.initTheme();
        this.initSidenav();
        this.initDropdowns();
        this.initTooltips();
        this.initModals();
        this.initSelects();
        this.initCharacterCounters();
        this.bindConfirms();
        this.initAutoRefresh();
        this.initLiveRefresh();
    },

    /* ---------- Partial auto-refresh of live sections ----------
     * Pages mark the parts that change with [data-live-section] and add an
     * #activity-watcher element with the initial state. While the worker / a
     * recheck / a queued command is active the marked sections are re-fetched,
     * and once it finishes they are refreshed a final time. The rest of the
     * page (forms, scroll, open menus) is left untouched: no full reload.
     */
    initAutoRefresh: function () {
        var watcher = document.getElementById('activity-watcher');
        var sections = document.querySelectorAll('[data-live-section]');
        if (!watcher || sections.length === 0) return;

        var activityUrl = watcher.getAttribute('data-url') || '/ajax_worker_activity.php';
        var pollInterval = parseInt(watcher.getAttribute('data-interval') || '5000', 10);
        var refreshInterval = parseInt(watcher.getAttribute('data-refresh-interval') || '10000', 10);
        var active = watcher.getAttribute('data-active') === '1';
        var version = watcher.getAttribute('data-version') || '';
        var lastRefresh = 0;
        var refreshing = false;

        function refreshSections() {
            if (refreshing) return;
            refreshing = true;
            lastRefresh = Date.now();
            fetch(window.location.pathname + window.location.search, {
                cache: 'no-store',
                headers: { 'X-Requested-With': 'fetch' }
            })
                .then(function (r) { return r.text(); })
                .then(function (html) {
                    var doc = new DOMParser().parseFromString(html, 'text/html');
                    document.querySelectorAll('[data-live-section]').forEach(function (el) {
                        var fresh = doc.getElementById(el.id);
                        if (!fresh) return;
                        el.innerHTML = fresh.innerHTML;
                        // Some sections toggle visibility via their class (e.g.
                        // the live worker card). Only those opt in, so tab panes
                        // keep their JS-managed "active" class.
                        if (el.hasAttribute('data-live-class')) {
                            el.className = fresh.className;
                        }
                    });
                    // Let pages refresh non-section parts (e.g. the TLD table
                    // rows) without a full reload.
                    document.dispatchEvent(new CustomEvent('tdl:refreshed'));
                })
                .catch(function () {})
                .then(function () { refreshing = false; });
        }

        // Expose the in-place refresh so a manual "Refresh" button can trigger
        // the same update without a full page reload.
        App.refreshLiveSections = refreshSections;

        function tick() {
            fetch(activityUrl, {
                headers: { 'Accept': 'application/json' },
                cache: 'no-store'
            })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (!d || !d.success) return;
                    var nowActive = !!d.active;
                    var newVersion = d.worker_version || '';
                    var versionChanged = !!newVersion && !!version && newVersion !== version;
                    var justFinished = active && !nowActive;

                    if (newVersion) version = newVersion;

                    if (justFinished || versionChanged) {
                        active = nowActive;
                        refreshSections();
                        return;
                    }

                    active = nowActive;
                    if (nowActive && Date.now() - lastRefresh >= refreshInterval) {
                        refreshSections();
                    }
                })
                .catch(function () {});
        }

        setInterval(tick, pollInterval);
        tick();
    },

    /* ---------- Manual "Refresh" buttons ----------
     * Buttons marked [data-refresh-live] reuse the in-place section refresh
     * (no full reload / no lost scroll). Falls back to a GET navigation.
     * Delegated on document so it survives section replacements. */
    initLiveRefresh: function () {
        document.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-refresh-live]');
            if (!btn) return;
            e.preventDefault();
            if (typeof App.refreshLiveSections === 'function') {
                App.refreshLiveSections();
            } else {
                window.location.href = window.location.pathname + window.location.search;
            }
        });
    },

    /* ---------- Theme (light / dark) ---------- */
    currentTheme: function () {
        return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    },

    applyTheme: function (theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            var icon = btn.querySelector('.material-icons');
            if (icon) {
                icon.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
            }
            btn.setAttribute('aria-label',
                theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        });
    },

    initTheme: function () {
        var self = this;
        this.applyTheme(this.currentTheme());
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                var next = self.currentTheme() === 'dark' ? 'light' : 'dark';
                try { localStorage.setItem(self.STORAGE_KEY, next); } catch (err) {}
                self.applyTheme(next);
            });
        });
    },

    // Elements with data-confirm ask for confirmation before acting
    bindConfirms: function () {
        document.querySelectorAll('[data-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                if (!window.confirm(this.getAttribute('data-confirm'))) {
                    e.preventDefault();
                    e.stopImmediatePropagation();
                }
            });
        });
    },

    // Mobile navigation drawer
    initSidenav: function () {
        var elems = document.querySelectorAll('.sidenav');
        if (elems.length && window.M) {
            M.Sidenav.init(elems, { edge: 'left', draggable: true });
        }
    },

    // Navbar / account / admin dropdowns
    initDropdowns: function () {
        var elems = document.querySelectorAll('.dropdown-trigger');
        if (elems.length && window.M) {
            M.Dropdown.init(elems, {
                coverTrigger: false,
                constrainWidth: false,
                hover: false,
                belowOrigin: true
            });
        }
    },

    initTooltips: function () {
        var elems = document.querySelectorAll('.tooltipped');
        if (elems.length && window.M) {
            M.Tooltip.init(elems, { margin: 6, inDuration: 250, outDuration: 150 });
        }
    },

    initModals: function () {
        var elems = document.querySelectorAll('.modal');
        if (elems.length && window.M) {
            M.Modal.init(elems, {
                dismissible: true,
                opacity: 0.5,
                inDuration: 250,
                outDuration: 200
            });
        }
    },

    // Style selects unless explicitly marked as browser-default
    initSelects: function () {
        var elems = document.querySelectorAll('select:not(.browser-default)');
        if (elems.length && window.M) {
            M.FormSelect.init(elems);
        }
    },

    initCharacterCounters: function () {
        var elems = document.querySelectorAll('input[data-length], textarea[data-length]');
        if (elems.length && window.M) {
            M.CharacterCounter.init(elems);
        }
    },

    // Toast notification helper
    toast: function (message, type) {
        if (!window.M) return;
        var classes = 'blue-grey darken-1';
        switch (type) {
            case 'success': classes = 'green darken-1'; break;
            case 'error': classes = 'red darken-1'; break;
            case 'warning': classes = 'amber darken-2'; break;
        }
        M.toast({ html: message, classes: classes, displayLength: 4000 });
    }
};

document.addEventListener('DOMContentLoaded', function () {
    App.init();
});
