import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test.describe('Admin and account layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('account renders the settings page header', async ({ page }) => {
    await page.goto('/account.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('.page-header h1')).toContainText('Email notifications');
    await expect(page.locator('.settings-card')).toBeVisible();
  });

  test('admin page has a unified header and working tabs', async ({ page }) => {
    await page.goto('/admin/');
    await expect(page.locator('.page-header h1')).toContainText('Administration');
    // The tab navigation still switches panes.
    await page.locator('#admin-tabs a[data-tab="commands"]').click();
    await expect(page.locator('.admin-pane[data-tab="commands"]').first()).toBeVisible();
  });

  test('tlds and update pages render their headers', async ({ page }) => {
    await page.goto('/admin/tlds.php');
    await expect(page.locator('.page-header h1')).toContainText('TLDs');
    await page.goto('/admin/update.php');
    await expect(page.locator('.page-header h1')).toContainText('System Update');
  });
});
