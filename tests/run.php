<?php
/**
 * Test runner: loads every tests/cases/*.php file and executes the registered
 * tests. Exit code 0 = all green, 1 = at least one failure.
 *
 * Usage:  php tests/run.php
 */
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$caseFiles = glob(__DIR__ . '/cases/*.php') ?: [];
sort($caseFiles);
foreach ($caseFiles as $file) {
    require $file;
}

$pass     = 0;
$fail     = 0;
$failures = [];

foreach ($GLOBALS['__tdl_tests'] as [$name, $fn]) {
    try {
        $fn();
        $pass++;
        echo "  PASS  $name\n";
    } catch (Throwable $e) {
        $fail++;
        $failures[] = [$name, $e->getMessage()];
        echo "  FAIL  $name\n";
    }
}

echo "\n" . count($GLOBALS['__tdl_tests']) . " tests: $pass passed, $fail failed\n";

if ($failures) {
    echo "\nFailures:\n";
    foreach ($failures as [$name, $msg]) {
        echo "  - $name: $msg\n";
    }
}

exit($fail === 0 ? 0 : 1);
