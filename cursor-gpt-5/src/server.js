const path = require('path');
const express = require('express');
const session = require('express-session');
const expressLayouts = require('express-ejs-layouts');
const SQLiteStore = require('connect-sqlite3')(session);
const compression = require('compression');
const pino = require('pino');
const pinoHttp = require('pino-http');
const { securityHeaders, globalRateLimiter } = require('./security');
const { getDb } = require('./db');
const config = require('./config');
const { defineRoutes } = require('./routes');

const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info', redact: ['req.headers.authorization', 'req.headers.cookie', 'req.body.password', 'res.headers[\"set-cookie\"]'] });

// Database init
getDb();

// Trust proxy if behind load balancer (for secure cookies)
if (config.trustProxy) {
    app.set('trust proxy', 1);
}

app.set('cookieName', config.cookieName);

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('layout', 'layout');
app.use(expressLayouts);

// Logging
app.use(pinoHttp({ logger }));

// Security headers
app.use(securityHeaders());

// Compression
app.use(compression());

// Body parsing with limits
app.use(express.urlencoded({ extended: false, limit: config.bodySizeLimit }));

// Static files
app.use('/static', express.static(path.join(__dirname, 'public'), { immutable: true, maxAge: '1y' }));

// Sessions
app.use(
    session({
        store: new SQLiteStore({ db: path.basename(config.sessionDbPath), dir: path.dirname(config.sessionDbPath) }),
        name: config.cookieName,
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: config.env === 'production',
            maxAge: 1000 * 60 * 60 * 12,
        },
    })
);

// Global rate limiter
app.use(globalRateLimiter());

// Routes
app.use(defineRoutes(app));

// Health check
app.get('/healthz', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ status: 'ok' });
});

// 404
app.use((req, res) => {
    res.status(404).render('error', { error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    req.log && req.log.error({ err }, 'unhandled_error');
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).render('error', { error: 'Invalid CSRF token' });
    }
    res.status(500).render('error', { error: 'Internal server error' });
});

app.listen(config.port, () => {
    logger.info(`Server listening on http://localhost:${config.port}`);
});


