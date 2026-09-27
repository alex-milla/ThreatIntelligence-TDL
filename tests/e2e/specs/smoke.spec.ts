import { test, expect } from '@playwright/test';
import { login } from '../helpers';

const PAGES = [
  { path: '/', title: 'Dashboard' },
  { path: '/notifications.php', title: 'Notifications' },
  { path: '/keywords.php', title: 'Keywords' },
  { path: '/watchlist.php', title: 'Watchlist' },
  { path: '/intelligence.php', title: 'Intelligence' },
  { path: '/iocs.php', title: 'IOCs' },
  { path: '/reports.php', title: 'Reports' },
  { path: '/account.php', title: 'Account' },
];

test.describe('Authenticated smoke test', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  for (const { path, title } of PAGES) {
    test(`renders ${path} without a server error`, async ({ page }) => {
      const response = await page.goto(path);
      expect(response, `no response for ${path}`).not.toBeNull();
      expect(response!.status(), `${path} returned ${response!.status()}`).toBeLessThan(500);
      await expect(page.locator('body')).toBeVisible();
      // The shared header renders the page title on every authenticated page.
      await expect(page.locator('.app-header-title')).toContainText(title);
    });
  }

  test('the seeded match is visible on the notifications page', async ({ page }) => {
    await page.goto('/notifications.php');
    await expect(page.getByText('acme-phishing.test').first()).toBeVisible();
  });

  test('admin Storage tab shows database and disk info', async ({ page }) => {
    await page.goto('/admin/#storage');
    const pane = page.locator('.admin-pane[data-tab="storage"]');
    await expect(pane).toBeVisible();
    await expect(pane).toContainText('app.db');
    await expect(pane).toContainText('Disk');
    await expect(pane).toContainText('Worker host');
    await expect(pane).toContainText('Zone downloads');
  });
});
