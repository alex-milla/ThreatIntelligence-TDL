<?php
/**
 * F5 hardening helpers: opt-in data directory (H2) and mail From domain
 * (H10.6).
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/public_html/includes/db.php';
require_once dirname(__DIR__, 2) . '/public_html/includes/mail.php';

function tdl_with_env_var(string $name, ?string $value, callable $fn): void {
    $old = getenv($name);
    if ($value === null) {
        putenv($name);
    } else {
        putenv($name . '=' . $value);
    }
    try {
        $fn();
    } finally {
        if ($old === false) {
            putenv($name);
        } else {
            putenv($name . '=' . $old);
        }
    }
}

test('tdl_data_dir honours TDL_DATA_DIR only when it exists', function () {
    $base = dirname(__DIR__) . '/tmp/datadir_' . bin2hex(random_bytes(4));
    @mkdir($base, 0777, true);
    try {
        tdl_with_env_var('TDL_DATA_DIR', $base, function () use ($base) {
            assert_same($base, tdl_data_dir());
        });
        tdl_with_env_var('TDL_DATA_DIR', $base . '/missing', function () {
            // A non-existent override must be ignored (default layout kept).
            assert_contains('data', tdl_data_dir());
            assert_same(false, str_contains(tdl_data_dir(), 'missing'));
        });
        tdl_with_env_var('TDL_DATA_DIR', null, function () {
            assert_contains('data', tdl_data_dir());
        });
    } finally {
        @rmdir($base);
    }
});

test('mail_from_domain prefers the env override over Host', function () {
    $oldHost = $_SERVER['HTTP_HOST'] ?? null;
    $_SERVER['HTTP_HOST'] = 'host.example.com';
    try {
        tdl_with_env_var('TDL_MAIL_FROM_DOMAIN', 'mail.example.com', function () {
            assert_same('mail.example.com', mail_from_domain());
        });
        // Invalid override falls back to the sanitised Host.
        tdl_with_env_var('TDL_MAIL_FROM_DOMAIN', 'bad domain!', function () {
            assert_same('host.example.com', mail_from_domain());
        });
        tdl_with_env_var('TDL_MAIL_FROM_DOMAIN', null, function () {
            assert_same('host.example.com', mail_from_domain());
        });
    } finally {
        if ($oldHost === null) {
            unset($_SERVER['HTTP_HOST']);
        } else {
            $_SERVER['HTTP_HOST'] = $oldHost;
        }
    }
});
