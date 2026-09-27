import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The seed gives keyword 1 ("acme") two matches: acme-phishing.test, acme-login.test.
test.describe('Keyword matches layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the breadcrumb, header and quick-filter chips', async ({ page }) => {
    await page.goto('/keyword_matches.php?id=1');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('body')).not.toContainText('Fatal error');
    await expect(page.locator('.breadcrumb')).toContainText('Keywords');
    await expect(page.locator('.breadcrumb')).toContainText('acme');
    await expect(page.locator('.page-header h1')).toContainText('acme');
    await expect(page.locator('.chip-tabs .chip')).toHaveCount(4);
  });

  test('clicking a domain opens the side drawer with compact actions', async ({ page }) => {
    await page.goto('/keyword_matches.php?id=1');
    await page.locator('a.domain-link').first().click();
    const drawer = page.locator('.drawer-panel.open');
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('.domain-detail')).toBeVisible();
    await expect(drawer.locator('.dd-actions-compact')).toBeVisible();
  });

  test('selecting rows reveals the contextual bulk toolbar', async ({ page }) => {
    await page.goto('/keyword_matches.php?id=1');
    await expect(page.locator('.context-toolbar')).toBeHidden();
    const checks = page.locator('tr[data-domain] .row-check');
    await checks.nth(0).check();
    await expect(page.locator('#bulk-form')).toHaveClass(/has-selection/);
    await expect(page.locator('.context-toolbar')).toBeVisible();
    await checks.nth(1).check();
    await expect(page.locator('body')).toHaveClass(/selection-mode/);
  });
});
