import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test.describe('Authentication', () => {
  test('anonymous access is redirected to login', async ({ page }) => {
    await page.goto('/watchlist.php');
    await expect(page).toHaveURL(/\/login\.php$/);
    await expect(page.locator('#login-form')).toBeVisible();
  });

  test('a valid login reaches the dashboard', async ({ page }) => {
    await login(page);
    await expect(page.locator('.app-sidebar')).toBeVisible();
    await expect(page.locator('.app-header-title')).toContainText('Dashboard');
  });

  test('an invalid password is rejected', async ({ page }) => {
    await page.goto('/login.php');
    await page.fill('#username', 'e2e_admin');
    await page.fill('#password', 'wrong-password');
    await page.click('#login-submit');
    await expect(page.locator('.login-error')).toContainText('Invalid username or password');
  });

  test('logout invalidates the session', async ({ page }) => {
    await login(page);
    await page.goto('/logout.php');
    await page.goto('/watchlist.php');
    await expect(page).toHaveURL(/\/login\.php$/);
  });
});
