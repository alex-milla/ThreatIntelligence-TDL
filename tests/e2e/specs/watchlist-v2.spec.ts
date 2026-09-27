import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The seed creates one ungrouped domain (watch-demo.test) and one in the
// "Clients" group (watch-clients.test).
test.describe('Watchlist layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the header, group chips and the domain table', async ({ page }) => {
    await page.goto('/watchlist.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('Watchlist');
    await expect(page.locator('.chip-tabs .chip')).toHaveCount(2);
    const row = page.locator('tr[data-domain="watch-demo.test"]:not(.domain-detail-row)');
    await expect(row).toBeVisible();
    // The grouped domain is not part of the default (Ungrouped) view.
    await expect(page.locator('tr[data-domain="watch-clients.test"]:not(.domain-detail-row)')).toHaveCount(0);
  });

  test('clicking a domain opens the side drawer with compact actions', async ({ page }) => {
    await page.goto('/watchlist.php');
    await page.locator('tr[data-domain="watch-demo.test"]:not(.domain-detail-row) .domain-link').click();
    const drawer = page.locator('.drawer-panel.open');
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('.domain-detail')).toBeVisible();
    await expect(drawer.locator('.dd-actions-compact')).toBeVisible();
  });

  test('a group chip filters to its own domains', async ({ page }) => {
    await page.goto('/watchlist.php?group=1');
    await expect(page.locator('tr[data-domain="watch-clients.test"]:not(.domain-detail-row)')).toBeVisible();
    await expect(page.locator('tr[data-domain="watch-demo.test"]:not(.domain-detail-row)')).toHaveCount(0);
  });
});
