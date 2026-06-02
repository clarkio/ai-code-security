'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const SqliteStore = require('better-sqlite3-session-store')(session);

const config = require('./config');
const db = require('./db');
const { exposeUser, csrf } = require('./middleware/security');
const authRoutes = require('./routes/auth');
const noteRoutes = require('./routes/notes');

const app = express();

// --- Trust proxy ----------------------------------------------------------
// Only trust the configured number of proxies. Trusting blindly would let a
// client spoof X-Forwarded-For (defeating rate limiting) or trick Express into
// thinking a plain-HTTP request was secure.
app.set('trust proxy', config.trustProxy);

// --- View engine ----------------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Security headers ------------------------------------------------------
// Helmet sets a strict set of headers. The CSP forbids inline scripts/styles,
// so even if an XSS payload slipped past EJS escaping it could not execute.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        ...(config.isProduction ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    // HSTS only meaningfully applies over HTTPS; harmless otherwise.
    hsts: config.isProduction
      ? { maxAge: 15552000, includeSubDomains: true }
      : false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// --- Global rate limit -----------------------------------------------------
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300, // generous app-wide ceiling; auth routes are stricter
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// --- Body parsing ----------------------------------------------------------
// Small body limits cap the damage from oversized-payload DoS attempts.
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

// --- Static assets ---------------------------------------------------------
app.use(
  express.static(path.join(__dirname, '..', 'public'), {
    maxAge: config.isProduction ? '1d' : 0,
    dotfiles: 'ignore',
  })
);

// --- Sessions --------------------------------------------------------------
app.use(
  session({
    name: 'sid', // generic name; don't advertise the framework
    store: new SqliteStore({
      client: db,
      expired: { clear: true, intervalMs: 15 * 60 * 1000 },
    }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true, // not readable by JS -> mitigates XSS cookie theft
      secure: config.isProduction, // HTTPS-only in production
      sameSite: 'lax', // mitigates CSRF
      maxAge: config.sessionMaxAgeMs,
      path: '/',
    },
  })
);

// --- Per-request locals & CSRF --------------------------------------------
app.use(exposeUser);
app.use(csrf);

// --- Routes ----------------------------------------------------------------
app.get('/', (req, res) =>
  res.redirect(req.session.userId ? '/notes' : '/login')
);
app.use('/', authRoutes);
app.use('/notes', noteRoutes);

// --- Health check (no secrets, no DB writes) -------------------------------
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// --- 404 -------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Not Found',
    message: 'The page you requested does not exist.',
  });
});

// --- Central error handler -------------------------------------------------
// Logs the full error server-side but never leaks internals to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  const status = err.status || 500;
  res.status(status).render('error', {
    title: 'Something went wrong',
    message: config.isProduction
      ? 'An unexpected error occurred. Please try again later.'
      : String(err && err.message),
  });
});

// --- Start -----------------------------------------------------------------
const server = app.listen(config.port, config.host, () => {
  console.log(
    `Secure Notes listening on http://${config.host}:${config.port} ` +
      `(${config.isProduction ? 'production' : 'development'})`
  );
});

// Graceful shutdown.
function shutdown(signal) {
  console.log(`\nReceived ${signal}, shutting down...`);
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = app;
