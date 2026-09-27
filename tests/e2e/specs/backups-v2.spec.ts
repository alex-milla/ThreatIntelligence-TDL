import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The seed creates 12 dummy backups; the Backups page keeps only the newest 10.
test.describe('Backups page', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the page and keeps only the 10 newest backups', async ({ page }) => {
    await page.goto('/admin/backups.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('Backups');
    await expect(page.locator('table tbody tr')).toHaveCount(10);
    await expect(page.locator('table tbody tr').first().getByRole('button', { name: /Restore/i })).toBeVisible();
  });

  test('the sidebar links to the Backups page', async ({ page }) => {
    await page.goto('/admin/');
    await expect(page.locator('a.sidebar-sublink[href="/admin/backups.php"]')).toBeVisible();
  });

  test('admin can queue a worker sync to the web version', async ({ page }) => {
    await page.goto('/admin/');
    const sync = page.getByRole('button', { name: /Sync worker to web version/i }).first();
    await expect(sync).toBeVisible();
    await sync.click();
    await expect(page.locator('.alert-success')).toContainText(/Worker sync to web version/i);
  });
});
