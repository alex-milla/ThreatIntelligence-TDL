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
    await expect(page.locator('.page-header')).toHaveCount(0);
    await expect(page.locator('.card-head')).toHaveCount(1);
  });

  test('v2 layout renders the header, KPIs and filter chips', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('.stat-strip .stat')).toHaveCount(4);
    await expect(page.locator('.chip-tabs .chip').first()).toBeVisible();
    await expect(page.locator('.page-header h1')).toContainText('Notifications');
    // The classic card header is not rendered in v2 (no duplicated title/action).
    await expect(page.locator('.page-header')).toHaveCount(1);
    await expect(page.locator('.card-head')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Mark All Read|Marcar todo leído/i })).toHaveCount(1);
  });

  test('clicking a domain opens the side drawer', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await page.locator('a.domain-link').first().click();
    const drawer = page.locator('.drawer-panel.open');
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('.domain-detail')).toBeVisible();
    // v2 uses the compact grouped actions, not the classic big button row.
    await expect(drawer.locator('.dd-actions-compact')).toBeVisible();
    await expect(drawer.locator('.dd-actions:not(.dd-actions-compact)')).toHaveCount(0);
    const compact = drawer.locator('.dd-actions-compact');
    await expect(compact).toContainText('CF Scan');
    await expect(compact).toContainText('CF DNS');
    await expect(compact).toContainText('Delete cache');
    await expect(compact).toContainText('Add to Watchlist');

    // The checks row stretches to the full width (equal buttons).
    const widths = await compact.locator('.dac-checks .btn').evaluateAll(
      (els) => els.map((e) => Math.round(e.getBoundingClientRect().width))
    );
    expect(widths.length).toBeGreaterThan(1);
    expect(Math.max(...widths) - Math.min(...widths)).toBeLessThanOrEqual(2);
    await page.locator('.drawer-close').click();
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);
  });

  test('the drawer swaps to the next domain without closing', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    const links = page.locator('a.domain-link');
    const first = (await links.nth(0).textContent())?.trim() || '';
    const second = (await links.nth(1).textContent())?.trim() || '';

    await links.nth(0).click();
    await expect(page.locator('.drawer-panel.open .drawer-title')).toHaveText(first);
    await expect(page.locator('body')).toHaveClass(/drawer-open/);

    // Clicking another domain updates the drawer in place (no close needed).
    await links.nth(1).click();
    await expect(page.locator('.drawer-panel.open .drawer-title')).toHaveText(second);
    await expect(page.locator('.drawer-panel.open')).toBeVisible();
  });

  test('selecting a row reveals the contextual toolbar', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');
    await page.locator('tr[data-domain] .row-check').first().check();
    await expect(page.locator('#bulk-form')).toHaveClass(/has-selection/);
    await expect(page.locator('.context-toolbar')).toBeVisible();
    await expect(page.locator('.context-toolbar .sel-count')).toContainText('1');
    // One selection keeps the sidebar (no selection mode yet).
    await expect(page.locator('body')).not.toHaveClass(/selection-mode/);
    await expect(page.locator('.app-sidebar')).toBeVisible();
  });

  test('selecting two rows enters selection mode and closes the detail drawer', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');

    // Open the detail drawer first.
    await page.locator('a.domain-link').first().click();
    await expect(page.locator('.drawer-panel.open')).toBeVisible();

    const checks = page.locator('tr[data-domain] .row-check');
    await checks.nth(0).check();
    await checks.nth(1).check();

    // Selection mode: the detail panel closes, the left nav stays visible.
    await expect(page.locator('body')).toHaveClass(/selection-mode/);
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);
    await expect(page.locator('.app-sidebar')).toBeVisible();
    await expect(page.locator('.context-toolbar')).toBeVisible();

    // Back to a single selection leaves selection mode.
    await checks.nth(1).uncheck();
    await expect(page.locator('body')).not.toHaveClass(/selection-mode/);
  });

  test('clicking a domain during selection mode opens the drawer and drops the other rows', async ({ page }) => {
    await page.goto('/notifications.php?ui=v2');

    const checks = page.locator('tr[data-domain] .row-check');
    await checks.nth(0).check();
    await checks.nth(1).check();
    await expect(page.locator('body')).toHaveClass(/selection-mode/);
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);

    // Clicking a domain takes over the selection instead of being closed by it.
    await page.locator('a.domain-link').first().click();
    await expect(page.locator('.drawer-panel.open')).toBeVisible();
    await expect(page.locator('body')).not.toHaveClass(/selection-mode/);
    // The clicked row keeps its check; the rest are cleared.
    await expect(checks.nth(0)).toBeChecked();
    await expect(checks.nth(1)).not.toBeChecked();
  });

  test('the classic layout still expands the detail inline', async ({ page }) => {
    await page.goto('/notifications.php?ui=classic');
    await page.locator('a.domain-link').first().click();
    // No drawer in classic; the inline detail row becomes visible instead.
    await expect(page.locator('.drawer-panel.open')).toHaveCount(0);
    await expect(page.locator('.domain-detail-row .domain-detail').first()).toBeVisible();
  });
});
