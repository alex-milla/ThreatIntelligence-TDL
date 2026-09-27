// UI layout v2 behaviours (loaded only under body.ui-v2).
//
// Reinterprets the server-rendered markup instead of duplicating it:
//  - the domain detail rows already rendered inline are shown in a side drawer;
//  - the always-on bulk actions become a contextual toolbar that appears only
//    when rows are selected (same forms, same names);
//  - Cmd/Ctrl+K focuses the page search box.
(function () {
    'use strict';

    function $(sel, root) { return (root || document).querySelector(sel); }
    function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

    /* ---------------- Side drawer (split, non-modal on desktop) ---------------- */
    var drawer = null;
    var backdrop = null;
    var lastFocus = null;
    var currentDomain = null;
    var currentRow = null;

    function buildDrawer() {
        if (drawer) return;
        backdrop = document.createElement('div');
        backdrop.className = 'drawer-backdrop';
        backdrop.addEventListener('click', closeDrawer);

        drawer = document.createElement('aside');
        drawer.className = 'drawer-panel';
        drawer.setAttribute('role', 'dialog');
        drawer.setAttribute('aria-label', 'Domain detail');
        drawer.innerHTML =
            '<div class="drawer-head">' +
            '<span class="drawer-title"></span>' +
            '<span class="spacer"></span>' +
            '<button type="button" class="drawer-close" aria-label="Close">' +
            '<i class="material-icons">close</i></button>' +
            '</div><div class="drawer-body"></div>';
        drawer.querySelector('.drawer-close').addEventListener('click', closeDrawer);

        document.body.appendChild(backdrop);
        document.body.appendChild(drawer);

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && drawer.classList.contains('open')) { closeDrawer(); }
        });
    }

    function setActiveRow(row) {
        $all('tr.dd-active').forEach(function (tr) { tr.classList.remove('dd-active'); });
        if (row) { row.classList.add('dd-active'); }
    }

    function openDrawer(domain, detailNode, row) {
        buildDrawer();
        // Clicking the domain that is already open closes the drawer.
        if (drawer.classList.contains('open') && currentDomain === domain) {
            closeDrawer();
            return;
        }
        drawer.querySelector('.drawer-title').textContent = domain;
        var body = drawer.querySelector('.drawer-body');
        body.innerHTML = '';
        if (detailNode) { body.appendChild(detailNode.cloneNode(true)); }
        body.scrollTop = 0;
        lastFocus = document.activeElement;
        currentDomain = domain;
        currentRow = row || null;
        setActiveRow(currentRow);
        backdrop.classList.add('open');
        drawer.classList.add('open');
        document.body.classList.add('drawer-open');
        if (currentRow && typeof currentRow.scrollIntoView === 'function') {
            currentRow.scrollIntoView({ block: 'nearest' });
        }
        var closeBtn = drawer.querySelector('.drawer-close');
        if (closeBtn) { closeBtn.focus(); }
    }

    function closeDrawer() {
        if (!drawer) return;
        drawer.classList.remove('open');
        backdrop.classList.remove('open');
        document.body.classList.remove('drawer-open');
        currentDomain = null;
        setActiveRow(null);
        if (lastFocus && typeof lastFocus.focus === 'function') { lastFocus.focus(); }
    }

    // Override the inline toggle: open the drawer instead of expanding the row.
    window.toggleDomainDetail = function (link, domain) {
        var row = link.closest ? link.closest('tr') : null;
        if (!row) return;
        var detailRow = row.nextElementSibling;
        if (!detailRow || !detailRow.classList.contains('domain-detail-row')) return;
        var detail = detailRow.querySelector('.domain-detail');
        if (!detail) return;
        openDrawer(domain || detailRow.getAttribute('data-domain') || '', detail, row);
    };

    /* ---------------- Contextual selection toolbar ---------------- */
    // The row checkboxes live in the table (outside the <form>, associated via
    // their `form="bulk-form"` attribute), so selection is read document-wide.
    function bulkForm() { return document.getElementById('bulk-form'); }

    function syncSelection(form) {
        form = form || bulkForm();
        if (!form) return;
        var all = $all('.row-check');
        var checked = all.filter(function (cb) { return cb.checked; });
        form.classList.toggle('has-selection', checked.length > 0);
        // From 2 selected rows: keep only the bulk bar and close the detail panel
        // (the left navigation stays visible).
        var selectionMode = checked.length >= 2;
        document.body.classList.toggle('selection-mode', selectionMode);
        if (selectionMode && drawer && drawer.classList.contains('open')) {
            closeDrawer();
        }
        var out = $('.sel-count', form);
        if (out) {
            out.textContent = checked.length + ' seleccionado' + (checked.length === 1 ? '' : 's');
        }
        var head = document.getElementById('select-all-head');
        if (head) {
            head.checked = all.length > 0 && checked.length === all.length;
            head.indeterminate = checked.length > 0 && checked.length < all.length;
        }
    }

    document.addEventListener('change', function (e) {
        var t = e.target;
        if (!t) return;
        if (t.classList && t.classList.contains('row-check')) {
            scheduleSync();
        } else if (t.id === 'select-all-head') {
            $all('.row-check').forEach(function (cb) { cb.checked = t.checked; });
            scheduleSync();
        }
    });

    // Click fallback: the themed checkbox may commit its checked state after the
    // change event, so re-read the selection on the next tick.
    document.addEventListener('click', function (e) {
        var t = e.target;
        if (!t || !t.closest) return;
        if (t.closest('tr[data-domain]') || t.closest('#select-all-head') || t.closest('.row-check')) {
            scheduleSync();
        }
    });

    function scheduleSync() {
        setTimeout(function () {
            requestAnimationFrame(function () { syncSelection(); });
        }, 50);
    }

    /* ---------------- Search shortcut (Cmd/Ctrl+K) ---------------- */
    document.addEventListener('keydown', function (e) {
        if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
            var q = document.getElementById('q') || $('input[type="search"]');
            if (q) { e.preventDefault(); q.focus(); q.select && q.select(); }
        }
    });

    document.addEventListener('DOMContentLoaded', function () {
        $all('#bulk-form').forEach(syncSelection);
    });
})();
