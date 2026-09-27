import { test, expect } from '@playwright/test';

// The E2E seed creates admin id 1 with api_key "e2e_api_key".
const API_KEY = 'e2e_api_key';

test.describe('Worker API', () => {
  test('a valid admin key returns data with rate-limit headers', async ({ request }) => {
    const res = await request.get('/api/v1/keywords.php', {
      headers: { 'X-API-Key': API_KEY },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);

    expect(res.headers()['x-ratelimit-limit']).toBeTruthy();
    expect(Number(res.headers()['x-ratelimit-remaining'])).toBeGreaterThanOrEqual(0);
    expect(Number(res.headers()['x-ratelimit-reset'])).toBeGreaterThan(0);
  });

  test('a missing key is rejected', async ({ request }) => {
    const res = await request.get('/api/v1/keywords.php');
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body.success).toBe(false);
  });
});
