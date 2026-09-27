import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The opt-in v2 layout is previewable per request with ?ui=v2 (admin only).
test.describe('Notifications v2 layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('classic layout has no v2 components', async ({ page }) => {
    await page.goto('/notifications.php?ui=classic');
    await expect(page.locator('body')).not.toHaveClass(/ui-v2/);
    await expect(page.locator('.stat-strip')).toHaveCount(0);
  });

  test('v2 layout renders the header, KPIs and filter chips', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('.stat-strip .stat')).toHaveCount(4);
    await expect(page.locator('.chip-tabs .chip').first()).toBeVisible();
    await expect(page.locator('.page-header h1')).toContainText('Notifications');
  });

  test('clicking a domain opens the side drawer', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await page.locator('a.domain-link').first().click();
    const drawer = page.locator('.drawer-panel.open');
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('.domain-detail')).toBeVisible();
    await page.locator('.drawer-close').click();
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);
  });

  test('selecting a row reveals the contextual toolbar', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await page.locator('tr[data-domain] .row-check').first().check();
    await expect(page.locator('#bulk-form')).toHaveClass(/has-selection/);
    await expect(page.locator('.context-toolbar')).toBeVisible();
    await expect(page.locator('.context-toolbar .sel-count')).toContainText('1');
  });

  test('the classic layout still expands the detail inline', async ({ page }) => {
    await page.goto('/notifications.php?ui=classic');
    await page.locator('a.domain-link').first().click();
    // No drawer in classic; the inline detail row becomes visible instead.
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);
    await expect(page.locator('.domain-detail-row .domain-detail').first()).toBeVisible();
  });
});
