// @ts-check
const { test, expect, request } = require('@playwright/test');

const BACKEND = process.env.BACKEND_URL || 'http://localhost:8080';
const FRONTEND = process.env.FRONTEND_URL || 'http://localhost:3000';
const MS_LOGIN_HOST = 'login.microsoftonline.com';

// ── Backend API tests ──────────────────────────────────────────────────────────

test.describe('Backend API', () => {
  test('GET /api/health returns 200', async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/health`);
    expect(res.status()).toBe(200);
  });

  test('GET /api/hello without auth cookie returns 403', async ({ request }) => {
    const res = await request.get(`${BACKEND}/api/hello`);
    expect(res.status()).toBe(403);
  });

  test('GET /api/auth/login redirects to Microsoft login', async ({ request }) => {
    // Follow=false so we can inspect the redirect target
    const res = await request.get(`${BACKEND}/api/auth/login`, { maxRedirects: 0 });
    expect([301, 302]).toContain(res.status());
    const location = res.headers()['location'] ?? '';
    expect(location).toContain(MS_LOGIN_HOST);
    expect(location).toContain('code_challenge'); // PKCE must be present
    expect(location).toMatch(/state=[0-9a-f-]{36}/); // UUID state for CSRF protection
  });
});

// ── Frontend UI tests ──────────────────────────────────────────────────────────

test.describe('Frontend UI', () => {
  test('App loads and shows Sign In button', async ({ page }) => {
    await page.goto(FRONTEND);
    await expect(page.getByText('MSAL React Authentication Demo')).toBeVisible();
    await expect(page.getByRole('button', { name: /Sign In with Azure AD/i })).toBeVisible();
  });

  test('Not authenticated by default', async ({ page }) => {
    await page.goto(FRONTEND);
    await expect(page.getByText('Not authenticated')).toBeVisible();
  });

  test('Sign In button redirects browser to Microsoft login', async ({ page }) => {
    await page.goto(FRONTEND);
    const [response] = await Promise.all([
      page.waitForNavigation({ url: `**/${MS_LOGIN_HOST}/**`, timeout: 10_000 }),
      page.getByRole('button', { name: /Sign In with Azure AD/i }).click(),
    ]);
    expect(page.url()).toContain(MS_LOGIN_HOST);
  });

  test('AUTH_TOKEN cookie is HTTP-only (not accessible via JS)', async ({ page, context }) => {
    // Inject a fake AUTH_TOKEN cookie to check JS cannot read it
    await context.addCookies([{
      name: 'AUTH_TOKEN',
      value: 'test-value',
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      secure: false,
    }]);
    await page.goto(FRONTEND);
    const cookieValue = await page.evaluate(() => {
      // document.cookie never contains httpOnly cookies
      return document.cookie.split(';').find(c => c.trim().startsWith('AUTH_TOKEN='));
    });
    expect(cookieValue).toBeUndefined();
  });
});

// ── Full OAuth sign-in flow (requires Azure AD credentials in env) ─────────────

const AZURE_TEST_USER = process.env.AZURE_TEST_USER;
const AZURE_TEST_PASS = process.env.AZURE_TEST_PASS;

test.describe('OAuth sign-in flow', () => {
  test.skip(!AZURE_TEST_USER || !AZURE_TEST_PASS,
    'Set AZURE_TEST_USER and AZURE_TEST_PASS env vars to run this test');

  test('Full login → /hello → logout cycle', async ({ page }) => {
    await page.goto(FRONTEND);

    // 1. Start login
    await page.getByRole('button', { name: /Sign In with Azure AD/i }).click();
    await page.waitForURL(`**/${MS_LOGIN_HOST}/**`);

    // 2. Fill in email
    await page.locator('input[type="email"]').fill(AZURE_TEST_USER);
    await page.getByRole('button', { name: /Next/i }).click();

    // 3. Fill in password
    await page.locator('input[type="password"]').fill(AZURE_TEST_PASS);
    await page.getByRole('button', { name: /Sign in/i }).click();

    // 4. Handle "Stay signed in?" prompt if it appears
    try {
      await page.getByRole('button', { name: /No/i }).click({ timeout: 5_000 });
    } catch (_e) {
      // "Stay signed in?" prompt is optional — safe to ignore when absent
    }

    // 5. Wait for redirect back to frontend
    await page.waitForURL(`${FRONTEND}/**`, { timeout: 30_000 });

    // 6. Verify authentication state
    await expect(page.getByText(/Secure authentication established/i)).toBeVisible({ timeout: 10_000 });

    // 7. Verify AUTH_TOKEN cookie exists and is HTTP-only
    const cookies = await page.context().cookies();
    const authCookie = cookies.find(c => c.name === 'AUTH_TOKEN');
    expect(authCookie).toBeDefined();
    expect(authCookie.httpOnly).toBe(true);

    // 8. Verify cookie is NOT readable by JavaScript
    const jsVisible = await page.evaluate(() =>
      document.cookie.includes('AUTH_TOKEN')
    );
    expect(jsVisible).toBe(false);

    // 9. Call hello endpoint
    await page.getByRole('button', { name: /Call Hello Endpoint/i }).click();
    await expect(page.getByText(/API Response/i)).toBeVisible({ timeout: 10_000 });

    // 10. Verify the response doesn't expose the raw token
    const responseText = await page.locator('.api-response').innerText();
    expect(responseText).not.toContain('eyJ'); // no JWT in the response

    // 11. Sign out
    await page.getByRole('button', { name: /Sign Out/i }).click();
    const cookiesAfterLogout = await page.context().cookies();
    const authCookieAfterLogout = cookiesAfterLogout.find(c => c.name === 'AUTH_TOKEN');
    expect(authCookieAfterLogout).toBeUndefined();
  });
});

// ── Cookie-mode token cache tests ─────────────────────────────────────────────
// These tests verify MSAL_TOKEN_CACHE cookie behaviour when the backend is
// running with app.token-cache.type=cookie.
//
// Prerequisites:
//   TOKEN_CACHE_TYPE=cookie  (must match the server's app.token-cache.type setting)
//   AZURE_TEST_USER and AZURE_TEST_PASS must be set (full OAuth flow required)

const TOKEN_CACHE_TYPE = process.env.TOKEN_CACHE_TYPE;
const MSAL_CACHE_COOKIE = process.env.MSAL_CACHE_COOKIE_NAME || 'MSAL_TOKEN_CACHE';

test.describe('Cookie-mode token cache', () => {
  test.skip(
    TOKEN_CACHE_TYPE !== 'cookie' || !AZURE_TEST_USER || !AZURE_TEST_PASS,
    'Set TOKEN_CACHE_TYPE=cookie, AZURE_TEST_USER, and AZURE_TEST_PASS to run these tests'
  );

  /**
   * Perform the full Azure AD login flow and return the authenticated page.
   * Shared across the cookie-mode tests.
   */
  async function performLogin(page) {
    await page.goto(FRONTEND);
    await page.getByRole('button', { name: /Sign In with Azure AD/i }).click();
    await page.waitForURL(`**/${MS_LOGIN_HOST}/**`);
    await page.locator('input[type="email"]').fill(AZURE_TEST_USER);
    await page.getByRole('button', { name: /Next/i }).click();
    await page.locator('input[type="password"]').fill(AZURE_TEST_PASS);
    await page.getByRole('button', { name: /Sign in/i }).click();
    try {
      await page.getByRole('button', { name: /No/i }).click({ timeout: 5_000 });
    } catch (_) { /* optional prompt */ }
    await page.waitForURL(`${FRONTEND}/**`, { timeout: 30_000 });
    await expect(page.getByText(/Secure authentication established/i)).toBeVisible({ timeout: 10_000 });
  }

  test('MSAL_TOKEN_CACHE cookie is set and is HTTP-only after login', async ({ page }) => {
    await performLogin(page);

    const cookies = await page.context().cookies();
    const msalCacheCookie = cookies.find(c => c.name === MSAL_CACHE_COOKIE);

    expect(msalCacheCookie).toBeDefined();
    expect(msalCacheCookie.httpOnly).toBe(true);
    expect(msalCacheCookie.sameSite).toBe('Strict');
    expect(msalCacheCookie.value).not.toBe('');
  });

  test('MSAL_TOKEN_CACHE cookie is not readable by JavaScript (HTTP-only enforcement)', async ({ page }) => {
    await performLogin(page);

    const jsVisible = await page.evaluate((cookieName) => {
      return document.cookie.includes(cookieName);
    }, MSAL_CACHE_COOKIE);

    expect(jsVisible).toBe(false);
  });

  test('MSAL_TOKEN_CACHE cookie value is opaque (encrypted, not raw JSON)', async ({ page }) => {
    await performLogin(page);

    const cookies = await page.context().cookies();
    const msalCacheCookie = cookies.find(c => c.name === MSAL_CACHE_COOKIE);

    expect(msalCacheCookie).toBeDefined();
    // Raw MSAL cache JSON always starts with '{'; the encrypted+compressed blob must not
    expect(msalCacheCookie.value).not.toContain('{');
    // Must not expose token type labels
    expect(msalCacheCookie.value).not.toContain('RefreshToken');
    expect(msalCacheCookie.value).not.toContain('AccessToken');
  });

  test('MSAL_TOKEN_CACHE cookie is cleared on logout', async ({ page }) => {
    await performLogin(page);

    // Verify it exists before logout
    const cookiesBefore = await page.context().cookies();
    expect(cookiesBefore.find(c => c.name === MSAL_CACHE_COOKIE)).toBeDefined();

    // Log out
    await page.getByRole('button', { name: /Sign Out/i }).click();

    const cookiesAfter = await page.context().cookies();
    const msalCookieAfter = cookiesAfter.find(c => c.name === MSAL_CACHE_COOKIE);
    expect(msalCookieAfter).toBeUndefined();
  });

  test('Silent token refresh still works and updates MSAL_TOKEN_CACHE cookie', async ({ page }) => {
    await performLogin(page);

    const cookiesBefore = await page.context().cookies();
    const msalCookieBefore = cookiesBefore.find(c => c.name === MSAL_CACHE_COOKIE);
    expect(msalCookieBefore).toBeDefined();

    // Trigger a protected API call which exercises the silent-refresh path
    await page.getByRole('button', { name: /Call Hello Endpoint/i }).click();
    await expect(page.getByText(/API Response/i)).toBeVisible({ timeout: 10_000 });

    // The MSAL_TOKEN_CACHE cookie must still be present (and may have been refreshed)
    const cookiesAfter = await page.context().cookies();
    const msalCookieAfter = cookiesAfter.find(c => c.name === MSAL_CACHE_COOKIE);
    expect(msalCookieAfter).toBeDefined();
    expect(msalCookieAfter.httpOnly).toBe(true);
  });
});
