<?php
/**
 * Self-updater helpers: ZIP path validation, manifest roundtrip, manifest-based
 * sync and pruning of files removed by a newer release (F2).
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/public_html/includes/updater.php';

function tdl_test_tmpdir(): string {
    $base = dirname(__DIR__) . '/tmp/upd_' . bin2hex(random_bytes(4));
    @mkdir($base, 0777, true);
    return $base;
}

function tdl_test_rmdir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
        $p = $dir . '/' . $f;
        is_dir($p) ? tdl_test_rmdir($p) : @unlink($p);
    }
    @rmdir($dir);
}

test('tdl_zip_entry_unsafe rejects traversal and absolute paths', function () {
    assert_false(tdl_zip_entry_unsafe('public_html/index.php'));
    assert_false(tdl_zip_entry_unsafe('worker/scheduler.py'));
    assert_true(tdl_zip_entry_unsafe('../etc/passwd'));
    assert_true(tdl_zip_entry_unsafe('a/../../b'));
    assert_true(tdl_zip_entry_unsafe('/etc/passwd'));
    assert_true(tdl_zip_entry_unsafe('C:/Windows/system32'));
    assert_true(tdl_zip_entry_unsafe("a\0b"));
    assert_true(tdl_zip_entry_unsafe(''));
});

test('manifest save/load roundtrip and sync only changed files', function () {
    $base = tdl_test_tmpdir();
    try {
        $src = $base . '/src';
        @mkdir($src . '/sub', 0777, true);
        file_put_contents($src . '/a.txt', 'A');
        file_put_contents($src . '/sub/b.txt', 'B');

        $dst = $base . '/dst';
        $m1 = [];
        $r1 = tdl_sync_tree($src, $dst, [], [], 'public_html/', $m1);
        assert_same(2, $r1['changed'], 'first sync copies both files');
        assert_same(2, count($m1));
        assert_true(isset($m1['public_html/a.txt']));
        assert_true(isset($m1['public_html/sub/b.txt']));

        // Second sync: identical content, nothing copied.
        $m2 = [];
        $r2 = tdl_sync_tree($src, $dst, [], [], 'public_html/', $m2);
        assert_same(0, $r2['changed']);
        assert_same(2, $r2['unchanged']);

        // Changed content is copied again.
        file_put_contents($src . '/a.txt', 'A2');
        $m3 = [];
        $r3 = tdl_sync_tree($src, $dst, [], [], 'public_html/', $m3);
        assert_same(1, $r3['changed']);
        assert_same('A2', file_get_contents($dst . '/a.txt'));

        // Manifest persists.
        assert_true(tdl_save_manifest($base . '/data', $m3));
        $loaded = tdl_load_manifest($base . '/data');
        assert_same($m3['public_html/a.txt'], $loaded['public_html/a.txt']);
    } finally {
        tdl_test_rmdir($base);
    }
});

test('tdl_prune_removed deletes only managed files gone from the release', function () {
    $base = tdl_test_tmpdir();
    try {
        $app = $base . '/app';
        @mkdir($app, 0777, true);
        file_put_contents($app . '/old.txt', 'old');
        file_put_contents($app . '/keep.txt', 'keep');
        file_put_contents($app . '/user-added.txt', 'mine');

        $prev = [
            'public_html/old.txt'  => 'x',
            'public_html/keep.txt' => 'y',
        ];
        $new = [
            'public_html/keep.txt' => 'y',
        ];
        $removed = tdl_prune_removed($prev, $new, $app, $base);
        assert_same(1, $removed);
        assert_false(is_file($app . '/old.txt'), 'managed removed file is deleted');
        assert_true(is_file($app . '/keep.txt'), 'managed kept file survives');
        assert_true(is_file($app . '/user-added.txt'), 'operator file is never deleted');
    } finally {
        tdl_test_rmdir($base);
    }
});

test('tdl_restore_backup reverts files and prunes post-backup additions', function () {
    $base = tdl_test_tmpdir();
    try {
        $app  = $base . '/app';
        $repo = $base . '/repo';
        @mkdir($app, 0777, true);
        @mkdir($repo, 0777, true);

        // Current state: A changed + a file added after the backup.
        file_put_contents($app . '/a.php', 'new-A');
        file_put_contents($app . '/extra.php', 'added-later');
        file_put_contents($app . '/user.txt', 'mine');
        tdl_save_manifest($app . '/data', [
            'public_html/a.php'     => hash('sha256', 'new-A'),
            'public_html/extra.php' => hash('sha256', 'added-later'),
        ]);

        // Backup holds the old A only.
        @mkdir($base . '/backup/backup_1/public_html', 0777, true);
        file_put_contents($base . '/backup/backup_1/public_html/a.php', 'old-A');

        $res = tdl_restore_backup($base . '/backup/backup_1', $app, $repo, $app . '/data');
        assert_true($res['success']);
        assert_same('old-A', file_get_contents($app . '/a.php'), 'file reverted');
        assert_false(is_file($app . '/extra.php'), 'post-backup managed file pruned');
        assert_true(is_file($app . '/user.txt'), 'operator file preserved');
    } finally {
        tdl_test_rmdir($base);
    }
});
