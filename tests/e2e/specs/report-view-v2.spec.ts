import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The seed stores one saved snapshot (id 1) with a single domain.
test.describe('Report view layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the report document', async ({ page }) => {
    await page.goto('/report_view.php?id=1');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.report-card')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Domain Threat Report' })).toBeVisible();
  });

  test('the domain Details opens in the lateral drawer', async ({ page }) => {
    await page.goto('/report_view.php?id=1');
    await page.locator('button.detail-toggle').first().click();
    const drawer = page.locator('.drawer-panel.open');
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('.domain-detail')).toBeVisible();
    await expect(drawer.locator('.dd-actions-compact')).toBeVisible();
  });
});
