process.env.NODE_ENV = 'test';
process.env.PORT = '3001';
process.env.TRUST_PROXY = 'false';
process.env.COOKIE_SECURE = 'false';
process.env.SESSION_PASSWORD = 'test-password-test-password-test-password-1234';
process.env.CSRF_SECRET = 'test-csrf-secret-test-csrf-secret-123456';
process.env.DATABASE_URL = 'file:./prisma/test.db';
process.env.LOG_LEVEL = 'silent';

import request from 'supertest';
import { createApp } from '../src/app';

describe('smoke', () => {
  test('GET / redirects to /login when logged out', async () => {
    const app = createApp();
    const res = await request(app).get('/');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('GET /login renders and sets security headers', async () => {
    const app = createApp();
    const res = await request(app).get('/login');

    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.text).toContain('name="_csrf"');
  });
});
