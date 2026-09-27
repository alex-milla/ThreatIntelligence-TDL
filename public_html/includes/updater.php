<?php
/**
 * Self-updater helpers (see skills/php-cms-updater).
 *
 * Manifest-based file sync for the self-hosted web app: only new/changed files
 * are copied, files that disappeared from the release (and were written by a
 * previous release) are pruned, ZIP entries are validated against path
 * traversal, and a backup can be restored. All helpers are pure/side-effect
 * scoped and never touch user data (data/, config.ini).
 *
 * The installed manifest lives at <dataDir>/.manifest.json and maps
 * "public_html/<rel>" or "worker/<rel>" to the SHA-256 of the shipped file.
 */

/**
 * Reject archive entries that could escape the extraction directory:
 * absolute paths, Windows drive paths, ".." traversal or NUL bytes.
 */
function tdl_zip_entry_unsafe(string $name): bool {
    if ($name === '' || strpos($name, "\0") !== false) {
        return true;
    }
    $n = str_replace('\\', '/', $name);
    if ($n[0] === '/' || preg_match('#^[A-Za-z]:#', $n)) {
        return true;
    }
    foreach (explode('/', $n) as $segment) {
        if ($segment === '..') {
            return true;
        }
    }
    return false;
}

function tdl_manifest_path(string $dataDir): string {
    return rtrim($dataDir, '/\\') . '/.manifest.json';
}

/**
 * @return array<string,string> path => sha256 (empty when no manifest yet).
 */
function tdl_load_manifest(string $dataDir): array {
    $path = tdl_manifest_path($dataDir);
    if (!is_file($path)) {
        return [];
    }
    $data = json_decode((string)@file_get_contents($path), true);
    return is_array($data) ? $data : [];
}

function tdl_save_manifest(string $dataDir, array $manifest): bool {
    if (!is_dir($dataDir)) {
        @mkdir($dataDir, 0755, true);
    }
    ksort($manifest);
    return @file_put_contents(
        tdl_manifest_path($dataDir),
        json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    ) !== false;
}

/**
 * Copy a directory tree, copying only new/changed files and recording their
 * hashes in $manifest under $prefix. Returns counts.
 *
 * @param array<int,string> $excludeTop  Top-level directory names to skip.
 * @param array<int,string> $excludeNames File basenames to skip.
 * @param array<string,string> $manifest  Updated by reference.
 * @return array{changed:int,unchanged:int}
 */
function tdl_sync_tree(
    string $src,
    string $dst,
    array $excludeTop,
    array $excludeNames,
    string $prefix,
    array &$manifest
): array {
    $changed = 0;
    $unchanged = 0;
    if (!is_dir($src)) {
        return ['changed' => 0, 'unchanged' => 0];
    }
    $rii = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($rii as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($src) + 1));
        $top = explode('/', $rel)[0];
        if (in_array($top, $excludeTop, true) || in_array(basename($rel), $excludeNames, true)) {
            continue;
        }
        $hash = @hash_file('sha256', $file->getPathname());
        if ($hash === false) {
            continue;
        }
        $manifest[$prefix . $rel] = $hash;
        $target = rtrim($dst, '/\\') . '/' . $rel;
        if (is_file($target) && @hash_file('sha256', $target) === $hash) {
            $unchanged++;
            continue;
        }
        @mkdir(dirname($target), 0755, true);
        if (@copy($file->getPathname(), $target)) {
            $changed++;
        }
    }
    return ['changed' => $changed, 'unchanged' => $unchanged];
}

/**
 * Resolve a manifest key to an absolute path (null when the prefix is unknown).
 */
function tdl_manifest_key_to_path(string $key, string $appRoot, string $repoRoot): ?string {
    if (strpos($key, 'public_html/') === 0) {
        return rtrim($appRoot, '/\\') . '/' . substr($key, strlen('public_html/'));
    }
    if (strpos($key, 'worker/') === 0) {
        return rtrim($repoRoot, '/\\') . '/worker/' . substr($key, strlen('worker/'));
    }
    return null;
}

/**
 * Delete files that a previous release installed but the new one no longer
 * ships. Only keys present in a previous manifest are ever deleted, so files
 * added by the operator are never touched.
 */
function tdl_prune_removed(array $prevManifest, array $newManifest, string $appRoot, string $repoRoot): int {
    $removed = 0;
    foreach ($prevManifest as $key => $_) {
        if (isset($newManifest[$key]) || strpos($key, '..') !== false) {
            continue;
        }
        $path = tdl_manifest_key_to_path($key, $appRoot, $repoRoot);
        if ($path !== null && is_file($path)) {
            if (@unlink($path)) {
                $removed++;
            }
        }
    }
    return $removed;
}

/**
 * Restore the app + worker files from a backup directory. The caller should
 * snapshot the current state first (backupApp) so the restore is reversible.
 *
 * @param string $backupDir Directory containing public_html/ (and worker/).
 * @return array{success:bool,changed?:int,removed?:int,error?:string}
 */
function tdl_restore_backup(string $backupDir, string $appRoot, string $repoRoot, string $dataDir): array {
    if (!is_dir($backupDir)) {
        return ['success' => false, 'error' => 'Backup directory not found.'];
    }
    $newManifest = [];
    $changed = 0;

    if (is_dir($backupDir . '/public_html')) {
        $r = tdl_sync_tree(
            $backupDir . '/public_html',
            $appRoot,
            ['data', '.git', '.github'],
            [],
            'public_html/',
            $newManifest
        );
        $changed += $r['changed'];
    }
    if (is_dir($backupDir . '/worker')) {
        $r = tdl_sync_tree(
            $backupDir . '/worker',
            rtrim($repoRoot, '/\\') . '/worker',
            ['data', 'logs', 'zones', '__pycache__'],
            ['config.ini'],
            'worker/',
            $newManifest
        );
        $changed += $r['changed'];
    }

    $prev = tdl_load_manifest($dataDir);
    $removed = tdl_prune_removed($prev, $newManifest, $appRoot, $repoRoot);
    tdl_save_manifest($dataDir, $newManifest);

    return ['success' => true, 'changed' => $changed, 'removed' => $removed];
}
