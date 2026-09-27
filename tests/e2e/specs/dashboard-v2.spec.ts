import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test.describe('Dashboard layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the page header and the KPI strip', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('Dashboard');
    // The KPI strip keeps its id/data-live-section for the in-place refresh.
    await expect(page.locator('#live-stats.stat-strip')).toHaveCount(1);
    await expect(page.locator('#live-stats .stat')).toHaveCount(4);
    await expect(page.locator('.page-header')).toHaveCount(1);
  });

  test('keeps the domain lookup and sparkline sections', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#lookup-q')).toBeVisible();
    await expect(page.locator('#glob-q')).toBeVisible();
    await expect(page.locator('#live-sparkline')).toHaveCount(1);
  });
});
