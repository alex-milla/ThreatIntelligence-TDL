import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { login } from '../helpers';

// browser-qa: axe-core covers ~30-40% of WCAG. A clean run is necessary, not
// sufficient; these tests gate on *critical* violations only and attach the
// full report for manual review (serious/moderate are surfaced, not failed).
function critical(violations: Awaited<ReturnType<AxeBuilder['analyze']>>['violations']) {
  return violations.filter((v) => v.impact === 'critical');
}

test('login page has no critical accessibility violations', async ({ page }, testInfo) => {
  await page.goto('/login.php');
  const results = await new AxeBuilder({ page }).analyze();
  await testInfo.attach('axe-login.json', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(critical(results.violations), JSON.stringify(critical(results.violations), null, 2)).toEqual([]);
});

test('dashboard has no critical accessibility violations', async ({ page }, testInfo) => {
  await login(page);
  const results = await new AxeBuilder({ page }).analyze();
  await testInfo.attach('axe-dashboard.json', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(critical(results.violations), JSON.stringify(critical(results.violations), null, 2)).toEqual([]);
});

test('notifications page has no critical accessibility violations', async ({ page }, testInfo) => {
  await login(page);
  await page.goto('/notifications.php');
  const results = await new AxeBuilder({ page }).analyze();
  await testInfo.attach('axe-notifications.json', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(critical(results.violations), JSON.stringify(critical(results.violations), null, 2)).toEqual([]);
});
