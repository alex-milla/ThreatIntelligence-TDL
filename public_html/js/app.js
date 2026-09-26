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
        this.initAdminSubmenu();
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

    // Elements with [data-confirm] ask for confirmation (themed modal) before
    // acting. Delegated on document so it also covers content injected later.
    bindConfirms: function () {
        document.addEventListener('click', function (e) {
            var el = e.target.closest ? e.target.closest('[data-confirm]') : null;
            if (!el || el._tdlConfirmed) return;
            e.preventDefault();
            e.stopImmediatePropagation();
            App.confirm({
                message: el.getAttribute('data-confirm'),
                title: el.getAttribute('data-confirm-title') || 'Please confirm',
                confirmText: el.getAttribute('data-confirm-ok') || 'Aceptar',
                danger: el.hasAttribute('data-confirm-danger')
            }).then(function (ok) {
                if (!ok) return;
                el._tdlConfirmed = true;
                var form = el.form || (el.tagName === 'FORM' ? el : null);
                if (form && el.type !== 'submit' && typeof form.requestSubmit === 'function') {
                    form.requestSubmit(el.tagName === 'BUTTON' ? el : undefined);
                } else {
                    el.click();
                }
                setTimeout(function () { el._tdlConfirmed = false; }, 0);
            });
        }, true);
    },

    // Mobile navigation drawer
    initSidenav: function () {
        var elems = document.querySelectorAll('.sidenav');
        if (elems.length && window.M) {
            M.Sidenav.init(elems, { edge: 'left', draggable: true });
        }
    },

    // Collapsible submenus in the sidebar / mobile drawer (TLDs, Admin Panel).
    // The wrapper (.sidebar-subgroup / .sidenav-subgroup) carries the is-open
    // class; the server pre-opens the group of the current area.
    initAdminSubmenu: function () {
        document.querySelectorAll('[data-submenu-toggle]').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                var id = btn.getAttribute('data-submenu-toggle');
                var menu = id ? document.getElementById(id) : null;
                if (!menu || !menu.parentElement) return;
                var wrap = menu.parentElement;
                var open = wrap.classList.toggle('is-open');
                btn.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
            // The drawer toggles are role="button" divs; support the keyboard.
            btn.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    btn.click();
                }
            });
        });
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

    // CSRF token from the page <meta> tag (also exposed as window.csrfToken()).
    csrf: function () {
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    },

    // Themed in-app notification (replaces window.alert). opts:
    //   {title, icon, actionLabel, onAction, timeout}
    // A toast with an action stays longer so the button can be pressed.
    toast: function (message, type, opts) {
        opts = opts || {};
        var stack = document.getElementById('tdl-toast-stack');
        if (!stack) {
            stack = document.createElement('div');
            stack.id = 'tdl-toast-stack';
            stack.className = 'tdl-toast-stack';
            document.body.appendChild(stack);
        }
        var kind = (type === 'success' || type === 'error' || type === 'warning') ? type : 'info';
        var icons = { success: 'check_circle', error: 'error', warning: 'warning', info: 'info' };

        var el = document.createElement('div');
        el.className = 'tdl-toast tdl-toast-' + kind;
        el.setAttribute('role', 'status');

        var icon = document.createElement('i');
        icon.className = 'material-icons tdl-toast-icon';
        icon.textContent = opts.icon || icons[kind];
        el.appendChild(icon);

        var body = document.createElement('div');
        body.className = 'tdl-toast-body';
        if (opts.title) {
            var title = document.createElement('span');
            title.className = 'tdl-toast-title';
            title.textContent = opts.title;
            body.appendChild(title);
        }
        var text = document.createElement('span');
        text.textContent = message;
        body.appendChild(text);
        el.appendChild(body);

        var removed = false;
        var timer = null;
        function dismiss() {
            if (removed) return;
            removed = true;
            if (timer) clearTimeout(timer);
            el.classList.remove('is-visible');
            el.classList.add('is-leaving');
            setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 220);
        }

        if (opts.actionLabel && typeof opts.onAction === 'function') {
            var action = document.createElement('button');
            action.type = 'button';
            action.className = 'tdl-toast-action';
            action.textContent = opts.actionLabel;
            action.addEventListener('click', function () {
                dismiss();
                opts.onAction();
            });
            el.appendChild(action);
        }

        var close = document.createElement('button');
        close.type = 'button';
        close.className = 'tdl-toast-close';
        close.setAttribute('aria-label', 'Close');
        close.innerHTML = '<i class="material-icons">close</i>';
        close.addEventListener('click', dismiss);
        el.appendChild(close);

        stack.appendChild(el);
        requestAnimationFrame(function () { el.classList.add('is-visible'); });

        var timeout = typeof opts.timeout === 'number'
            ? opts.timeout
            : (opts.actionLabel ? 10000 : 5000);
        if (timeout > 0) timer = setTimeout(dismiss, timeout);
        return dismiss;
    },

    // Themed confirmation dialog (replaces window.confirm). Returns a Promise
    // resolving true (Aceptar) or false (Cancelar / Esc / click outside).
    confirm: function (opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var overlay = document.createElement('div');
            overlay.className = 'tdl-modal-overlay';

            var modal = document.createElement('div');
            modal.className = 'tdl-modal';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');

            var head = document.createElement('div');
            head.className = 'tdl-modal-head';
            var hIcon = document.createElement('i');
            hIcon.className = 'material-icons';
            hIcon.textContent = opts.icon || (opts.danger ? 'warning' : 'help_outline');
            var hText = document.createElement('span');
            hText.textContent = opts.title || 'Please confirm';
            head.appendChild(hIcon);
            head.appendChild(hText);
            modal.appendChild(head);

            var body = document.createElement('div');
            body.className = 'tdl-modal-body';
            var p = document.createElement('p');
            p.textContent = opts.message || '';
            body.appendChild(p);
            modal.appendChild(body);

            var actions = document.createElement('div');
            actions.className = 'tdl-modal-actions';
            var cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'btn btn-outline waves-effect';
            cancelBtn.textContent = opts.cancelText || 'Cancelar';
            var okBtn = document.createElement('button');
            okBtn.type = 'button';
            okBtn.className = 'btn waves-effect ' + (opts.danger ? 'btn-danger' : '');
            okBtn.textContent = opts.confirmText || 'Aceptar';
            actions.appendChild(cancelBtn);
            actions.appendChild(okBtn);
            modal.appendChild(actions);

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            requestAnimationFrame(function () { overlay.classList.add('is-visible'); });

            function onKey(e) {
                if (e.key === 'Escape') { close(false); }
                else if (e.key === 'Enter') { e.preventDefault(); close(true); }
            }
            function close(result) {
                document.removeEventListener('keydown', onKey);
                overlay.classList.remove('is-visible');
                setTimeout(function () { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }, 200);
                resolve(result);
            }
            cancelBtn.addEventListener('click', function () { close(false); });
            okBtn.addEventListener('click', function () { close(true); });
            overlay.addEventListener('click', function (e) { if (e.target === overlay) close(false); });
            document.addEventListener('keydown', onKey);
            okBtn.focus();
        });
    },

    // Themed text prompt (replaces window.prompt). Resolves the string, or null
    // if cancelled. opts: {title, message, value, placeholder, confirmText}.
    prompt: function (opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var overlay = document.createElement('div');
            overlay.className = 'tdl-modal-overlay';

            var modal = document.createElement('div');
            modal.className = 'tdl-modal';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');

            var head = document.createElement('div');
            head.className = 'tdl-modal-head';
            var hIcon = document.createElement('i');
            hIcon.className = 'material-icons';
            hIcon.textContent = opts.icon || 'edit';
            var hText = document.createElement('span');
            hText.textContent = opts.title || 'Input';
            head.appendChild(hIcon);
            head.appendChild(hText);
            modal.appendChild(head);

            var body = document.createElement('div');
            body.className = 'tdl-modal-body';
            if (opts.message) {
                var p = document.createElement('p');
                p.textContent = opts.message;
                body.appendChild(p);
            }
            var field = document.createElement('div');
            field.className = 'tdl-modal-input';
            var input = document.createElement('input');
            input.type = opts.type || 'text';
            input.value = opts.value != null ? opts.value : '';
            if (opts.placeholder) input.placeholder = opts.placeholder;
            field.appendChild(input);
            body.appendChild(field);
            modal.appendChild(body);

            var actions = document.createElement('div');
            actions.className = 'tdl-modal-actions';
            var cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'btn btn-outline waves-effect';
            cancelBtn.textContent = opts.cancelText || 'Cancelar';
            var okBtn = document.createElement('button');
            okBtn.type = 'button';
            okBtn.className = 'btn waves-effect';
            okBtn.textContent = opts.confirmText || 'Aceptar';
            actions.appendChild(cancelBtn);
            actions.appendChild(okBtn);
            modal.appendChild(actions);

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            requestAnimationFrame(function () { overlay.classList.add('is-visible'); });

            function onKey(e) {
                if (e.key === 'Escape') { close(null); }
                else if (e.key === 'Enter') { e.preventDefault(); close(input.value); }
            }
            function close(result) {
                document.removeEventListener('keydown', onKey);
                overlay.classList.remove('is-visible');
                setTimeout(function () { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }, 200);
                resolve(result);
            }
            cancelBtn.addEventListener('click', function () { close(null); });
            okBtn.addEventListener('click', function () { close(input.value); });
            overlay.addEventListener('click', function (e) { if (e.target === overlay) close(null); });
            document.addEventListener('keydown', onKey);
            input.focus();
            if (input.select) input.select();
        });
    }
};

// Expose the CSRF helper globally so the asset scripts share one implementation
// (some of them call a bare csrfToken()).
window.csrfToken = window.csrfToken || function () { return App.csrf(); };

document.addEventListener('DOMContentLoaded', function () {
    App.init();
});

// Enable the global theme transition only after the first paint, so the
// initial render never animates but light/dark switches fade smoothly.
window.addEventListener('load', function () {
    document.documentElement.classList.add('transition-theme');
});
