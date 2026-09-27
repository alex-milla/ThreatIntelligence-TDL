<?php
/**
 * Theme helpers: value whitelisting and server-side cookie resolution
 * (F4.3, skills/php-cms-theme).
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/public_html/includes/theme.php';

test('tdl_normalize_theme whitelists light/dark only', function () {
    assert_same('light', tdl_normalize_theme('light'));
    assert_same('dark', tdl_normalize_theme('dark'));
    assert_same('light', tdl_normalize_theme('evil'));
    assert_same('light', tdl_normalize_theme(''));
});

test('tdl_resolve_theme reads the tdl_theme cookie', function () {
    $old = $_COOKIE;
    try {
        $_COOKIE = [];
        assert_same('light', tdl_resolve_theme(), 'default is light');

        $_COOKIE['tdl_theme'] = 'dark';
        assert_same('dark', tdl_resolve_theme());

        $_COOKIE['tdl_theme'] = 'evil<script>';
        assert_same('light', tdl_resolve_theme(), 'untrusted value falls back to light');
    } finally {
        $_COOKIE = $old;
    }
});

test('tdl_theme_boot_script is a self-contained inline script', function () {
    $js = tdl_theme_boot_script();
    assert_contains('<script>', $js);
    assert_contains('tdl-theme', $js);
    assert_contains('data-theme', $js);
});
