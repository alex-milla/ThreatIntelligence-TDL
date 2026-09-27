<?php
/**
 * Light/dark theme helpers (see skills/php-cms-theme).
 *
 * The theme is resolved server-side from the `tdl_theme` cookie so the first
 * paint is correct even before (or without) JavaScript. The client keeps using
 * localStorage for instant toggling and mirrors the choice into the cookie, and
 * the inline boot script only overrides the server value when the visitor has an
 * explicit saved preference.
 */

function tdl_normalize_theme(string $theme): string {
    return in_array($theme, ['light', 'dark'], true) ? $theme : 'light';
}

/** Theme to render in the initial HTML (cookie wins, defaults to light). */
function tdl_resolve_theme(): string {
    if (isset($_COOKIE['tdl_theme'])) {
        return tdl_normalize_theme((string)$_COOKIE['tdl_theme']);
    }
    return 'light';
}

/** Inline <head> script: apply the saved localStorage preference before paint. */
function tdl_theme_boot_script(): string {
    return '<script>(function(){try{var t=localStorage.getItem("tdl-theme");'
        . 'if(t==="dark"||t==="light"){document.documentElement.setAttribute("data-theme",t);}'
        . '}catch(e){}})();</script>';
}
