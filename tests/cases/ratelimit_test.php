<?php
/**
 * Rate-limiting helpers against an in-memory SQLite database (H10.1/H10.4).
 * The helpers take a PDO, so they are testable without booting the app DB.
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/public_html/includes/auth.php';

function tdl_test_db(): PDO {
    $db = new PDO('sqlite::memory:');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("CREATE TABLE register_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");
    $db->exec("CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        username TEXT,
        attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");
    return $db;
}

test('isRegisterRateLimited blocks one IP but not others', function () {
    $db = tdl_test_db();
    for ($i = 0; $i < 5; $i++) {
        recordRegisterAttempt($db, '198.51.100.5');
    }
    assert_true(isRegisterRateLimited($db, '198.51.100.5'));
    assert_false(isRegisterRateLimited($db, '198.51.100.6'));
});

test('recordLoginAttempt is counted and bounded', function () {
    $db = tdl_test_db();
    recordLoginAttempt($db, '198.51.100.7', 'admin');
    assert_false(isRateLimited($db, '198.51.100.7', 5, 15));
    for ($i = 0; $i < 4; $i++) {
        recordLoginAttempt($db, '198.51.100.7', 'admin');
    }
    assert_true(isRateLimited($db, '198.51.100.7', 5, 15));
});
