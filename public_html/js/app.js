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
