// Prepare an isolated E2E environment and start PHP's built-in server.
//
// 1. Copy public_html/ to .e2e/docroot (throwaway; never touches the real app).
// 2. Seed a known admin + a sample match/notification via seed.php.
// 3. Serve .e2e/docroot on 127.0.0.1:$E2E_PORT with `php -S`.
//
// Playwright launches this as its webServer and waits for /login.php.
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const e2eRoot = path.join(repo, '.e2e');
const docroot = path.join(e2eRoot, 'docroot');
const port = process.env.E2E_PORT || '8123';
const php = process.env.PHP_BIN || 'php';

rmSync(docroot, { recursive: true, force: true });
mkdirSync(e2eRoot, { recursive: true });
cpSync(path.join(repo, 'public_html'), docroot, { recursive: true });

const seed = spawnSync(
  php,
  [path.join(repo, 'tests', 'e2e', 'scripts', 'seed.php'), docroot],
  { stdio: 'inherit', cwd: repo }
);
if (seed.status !== 0) {
  console.error('E2E seed failed (is PHP on PATH?)');
  process.exit(seed.status || 1);
}

const server = spawn(php, ['-S', `127.0.0.1:${port}`, '-t', docroot], {
  stdio: 'inherit',
  cwd: repo,
});
server.on('exit', (code) => process.exit(code ?? 0));
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.kill(sig));
}
