import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test.describe('IOCs layout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('renders the header, count chip and filters', async ({ page }) => {
    await page.goto('/iocs.php');
    await expect(page.locator('body')).toHaveClass(/ui-v2/);
    await expect(page.locator('body')).not.toContainText('Warning:');
    await expect(page.locator('.page-header h1')).toContainText('IOCs');
    await expect(page.locator('.page-header .count-chip')).toBeVisible();
    await expect(page.locator('.filter-form select[name="source"]')).toBeVisible();
    await expect(page.locator('.filter-form select[name="severity"]')).toBeVisible();
    await expect(page.getByRole('link', { name: /Download TXT/i })).toBeVisible();
  });
});
