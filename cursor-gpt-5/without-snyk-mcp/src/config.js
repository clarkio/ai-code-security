const dotenv = require('dotenv');
dotenv.config();

const required = (value, name) => {
    if (value === undefined || value === null || value === '') return undefined;
    return value;
};

module.exports = {
    env: process.env.NODE_ENV || 'development',
    port: Number(process.env.PORT || 3000),
    sessionSecret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
    trustProxy: process.env.TRUST_PROXY === 'true',
    rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
    rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 200),
    authRateLimitMax: Number(process.env.AUTH_RATE_LIMIT_MAX || 20),
    bodySizeLimit: process.env.BODY_SIZE_LIMIT || '64kb',
    dbPath: process.env.DB_PATH || 'data/notes.sqlite3',
    sessionDbPath: process.env.SESSION_DB_PATH || 'data/sessions.sqlite3',
    cookieName: process.env.SESSION_COOKIE_NAME || 'sid',
    allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
};


