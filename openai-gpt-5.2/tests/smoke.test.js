"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
process.env.NODE_ENV = 'test';
process.env.PORT = '3001';
process.env.TRUST_PROXY = 'false';
process.env.COOKIE_SECURE = 'false';
process.env.SESSION_PASSWORD = 'test-password-test-password-test-password-1234';
process.env.CSRF_SECRET = 'test-csrf-secret-test-csrf-secret-123456';
process.env.DATABASE_URL = 'file:./prisma/test.db';
process.env.LOG_LEVEL = 'silent';
const supertest_1 = __importDefault(require("supertest"));
const app_1 = require("../src/app");
describe('smoke', () => {
    test('GET / redirects to /login when logged out', async () => {
        const app = (0, app_1.createApp)();
        const res = await (0, supertest_1.default)(app).get('/');
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('/login');
    });
    test('GET /login renders and sets security headers', async () => {
        const app = (0, app_1.createApp)();
        const res = await (0, supertest_1.default)(app).get('/login');
        expect(res.status).toBe(200);
        expect(res.headers['content-security-policy']).toContain("default-src 'self'");
        expect(res.text).toContain('name="_csrf"');
    });
});
