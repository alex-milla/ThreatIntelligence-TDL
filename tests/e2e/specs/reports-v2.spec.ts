import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test.describe('Reports layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the header, queue/history chips and group chips', async ({ page }) => {
    await page.goto('/reports.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('Reports');
    await expect(page.locator('.chip-tabs .chip', { hasText: 'Queue' })).toBeVisible();
    await expect(page.locator('.chip-tabs .chip', { hasText: 'History' })).toBeVisible();
  });

  test('the history tab is reachable and marks its chip active', async ({ page }) => {
    await page.goto('/reports.php?tab=history');
    await expect(page.locator('.page-header h1')).toContainText('Reports');
    await expect(page.locator('.chip-tabs .chip.active', { hasText: 'History' })).toBeVisible();
  });
});
