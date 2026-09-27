import { test, expect } from '@playwright/test';
import { login } from '../helpers';

// The seed creates one tracked domain (track-demo.test).
test.describe('Intelligence layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the header, status chips, search and the table', async ({ page }) => {
    await page.goto('/intelligence.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('Intelligence');
    await expect(page.locator('.chip-tabs .chip')).toHaveCount(4);
    await expect(page.locator('#q')).toBeVisible();
    await expect(page.getByText('track-demo.test').first()).toBeVisible();
  });

  test('the row action menu opens (shared toggleMenu)', async ({ page }) => {
    await page.goto('/intelligence.php');
    await page.locator('.action-menu-btn').first().click();
    await expect(page.locator('.action-menu-dropdown.active')).toBeVisible();
  });

  test('a status chip filters the list', async ({ page }) => {
    await page.goto('/intelligence.php?status=dormant');
    // Only the dormant filter is active; the tracked row is not dormant.
    await expect(page.locator('.chip-tabs .chip.active')).toContainText('Dormant');
    await expect(page.locator('table tbody tr')).toHaveCount(0);
  });
});
