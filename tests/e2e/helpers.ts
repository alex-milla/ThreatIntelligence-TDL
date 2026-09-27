import { Page, expect } from '@playwright/test';

export const E2E_USER = 'e2e_admin';
export const E2E_PASS = 'e2e_password_123';

/** Log in through the real form (CSRF, bcrypt) and land on the dashboard. */
export async function login(page: Page): Promise<void> {
  await page.goto('/login.php');
  await expect(page.locator('#login-form')).toBeVisible();
  await page.fill('#username', E2E_USER);
  await page.fill('#password', E2E_PASS);
  await page.click('#login-submit');
  await page.waitForURL((url) => !url.pathname.endsWith('/login.php'), { timeout: 15_000 });
  await expect(page.locator('.app-header-title')).toContainText('Dashboard');
}
