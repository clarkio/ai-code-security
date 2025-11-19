const dotenv = require('dotenv');

dotenv.config();

const required = ['SESSION_SECRET'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
  throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
}

const env = process.env.NODE_ENV || 'development';

module.exports = {
  env,
  port: Number(process.env.PORT) || 3000,
  sessionSecret: process.env.SESSION_SECRET,
  adminPassword: process.env.ADMIN_PASSWORD || null,
  adminUsername: process.env.ADMIN_USERNAME || 'admin',
  trustProxy: process.env.TRUST_PROXY === '1',
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || 100,
  dbFile: process.env.DB_FILE || './data/notes.db',
  secureCookies: process.env.SECURE_COOKIES === '1' || env === 'production',
  allowRegistration: process.env.ALLOW_REGISTRATION !== '0',
};
