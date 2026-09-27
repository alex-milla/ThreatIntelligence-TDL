import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// v2 is the only layout. The seed creates three keywords: acme (off, 2 matches),
// beta (tracking on) and gamma (off, 5 matches).
test.describe('Keywords layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the header, KPIs and the search/filter bar', async ({ page }) => {
    await page.goto('/keywords.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('body')).not.toContainText('Fatal error');
    await expect(page.locator('.page-header h1')).toContainText('Keywords');
    const stats = page.locator('.stat-strip .stat');
    await expect(stats).toHaveCount(3);
    await expect(stats.nth(0)).toContainText('Keywords');
    await expect(stats.nth(1)).toContainText('Matches');
    await expect(stats.nth(2)).toContainText('Tracking');
    await expect(page.locator('#q')).toBeVisible();
    await expect(page.locator('#kw-filter')).toBeVisible();
  });

  test('Add Keyword reveals the form on demand', async ({ page }) => {
    await page.goto('/keywords.php');
    await expect(page.locator('#kw-add')).toBeHidden();
    await page.getByRole('button', { name: /Add Keyword/i }).click();
    await expect(page.locator('#kw-add')).toBeVisible();
    await expect(page.locator('#keyword')).toBeVisible();
  });

  test('searching filters the keyword rows', async ({ page }) => {
    await page.goto('/keywords.php');
    await page.locator('#q').fill('beta');
    await expect(page.locator('tr[data-keyword="beta"]')).toBeVisible();
    await expect(page.locator('tr[data-keyword="acme"]')).toBeHidden();
    await expect(page.locator('tr[data-keyword="gamma"]')).toBeHidden();
  });

  test('the tracking filter narrows the list', async ({ page }) => {
    await page.goto('/keywords.php');
    await page.locator('#kw-filter').selectOption('on');
    await expect(page.locator('tr[data-keyword="beta"]')).toBeVisible();
    await expect(page.locator('tr[data-keyword="acme"]')).toBeHidden();
    await page.locator('#kw-filter').selectOption('off');
    await expect(page.locator('tr[data-keyword="gamma"]')).toBeVisible();
    await expect(page.locator('tr[data-keyword="beta"]')).toBeHidden();
  });

  test('selecting a keyword reveals the bulk recheck bar', async ({ page }) => {
    await page.goto('/keywords.php');
    await expect(page.locator('#kw-selection')).toBeHidden();
    await page.locator('tr[data-keyword="acme"] .kw-check').check();
    await expect(page.locator('#kw-selection')).toBeVisible();
    await expect(page.locator('#kw-selection .sel-count')).toContainText('1');
    await page.getByRole('button', { name: /^Clear$/i }).click();
    await expect(page.locator('#kw-selection')).toBeHidden();
  });
});
