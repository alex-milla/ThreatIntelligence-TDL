import { test, expect } from '@playwright/test';
import { login } from '../helpers';

test('theme toggle switches to dark and persists via cookie', async ({ page, context }) => {
  await login(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

  await page.locator('[data-theme-toggle]').first().click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === 'tdl_theme')?.value).toBe('dark');

  // The server renders the cookie value on the next load (no FOUC).
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});
