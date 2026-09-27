<?php
/**
 * Minimal, dependency-free test harness for the PHP application.
 *
 * There is no Composer/PHPUnit requirement: run the whole suite with
 *   php tests/run.php
 * which exits non-zero on the first failing assertion set. Designed to stay in
 * the repository without shipping to the web root (the updater only copies
 * public_html/ and worker/).
 */
declare(strict_types=1);

// Keep sessions functional (and quiet) in the CLI test process. These must run
// before any output, so no diagnostics are emitted here.
ini_set('session.cache_limiter', '');
$__tdl_tmp = sys_get_temp_dir();
if ($__tdl_tmp !== '') {
    session_save_path($__tdl_tmp);
}

$GLOBALS['__tdl_tests'] = [];

function test(string $name, callable $fn): void {
    $GLOBALS['__tdl_tests'][] = [$name, $fn];
}

function assert_true($cond, string $msg = 'expected true'): void {
    if ($cond !== true) {
        throw new RuntimeException($msg);
    }
}

function assert_false($cond, string $msg = 'expected false'): void {
    if ($cond !== false) {
        throw new RuntimeException($msg);
    }
}

function assert_same($expected, $actual, string $msg = ''): void {
    if ($expected !== $actual) {
        throw new RuntimeException(
            ($msg !== '' ? $msg . ': ' : '')
            . 'expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true)
        );
    }
}

function assert_contains(string $needle, string $haystack, string $msg = ''): void {
    if (strpos($haystack, $needle) === false) {
        throw new RuntimeException(
            ($msg !== '' ? $msg . ': ' : '') . "expected to find '$needle'"
        );
    }
}
