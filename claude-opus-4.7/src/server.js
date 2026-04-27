'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const Database = require('better-sqlite3');
const SqliteStore = require('better-sqlite3-session-store')(session);

const config = require('./config');
const { attachUser } = require('./middleware/auth');
const { csrfMiddleware } = require('./middleware/csrf');
const { globalLimiter } = require('./middleware/rateLimit');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

// Touch the DB module so the schema is created and pragmas applied.
require('./db');

const app = express();

// Disable the X-Powered-By header (helmet also handles this, defense in depth).
app.disable('x-powered-by');

// Trust proxy must be explicit. Setting `true` blindly lets an attacker spoof
// X-Forwarded-For. Use a single hop by default when enabled.
if (config.trustProxy) {
  app.set('trust proxy', 1);
}

// Views.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security headers, including a strict Content-Security-Policy that blocks
// inline scripts and inline styles. All assets must come from same-origin.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'object-src': ["'none'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'upgrade-insecure-requests': config.isProd ? [] : null,
      },
    },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'same-origin' },
    hsts: config.isProd
      ? { maxAge: 31536000, includeSubDomains: true, preload: false }
      : false,
    frameguard: { action: 'deny' },
    noSniff: true,
  }),
);

// Global rate limiter — applied before parsers so flooders don't burn CPU.
app.use(globalLimiter);

// Body parsers with strict size limits. JSON parser is included but the app
// only accepts urlencoded forms; keeping JSON disabled would break nothing.
app.use(express.urlencoded({ extended: false, limit: config.limits.bodyUrlencodedBytes }));
app.use(express.json({ limit: config.limits.bodyJsonBytes }));

// Static assets. `public/` only contains the stylesheet; no user data is
// served from disk. dotfiles=ignore prevents accidental dotfile exposure.
app.use(
  '/static',
  express.static(path.join(__dirname, '..', 'public'), {
    dotfiles: 'ignore',
    index: false,
    fallthrough: true,
    maxAge: config.isProd ? '7d' : 0,
  }),
);

// Sessions: server-side store, signed cookie, strict SameSite, httpOnly,
// Secure in production. Session id is regenerated on login (see auth route).
const sessionsDir = path.join(path.dirname(config.databasePath));
fs.mkdirSync(sessionsDir, { recursive: true, mode: 0o700 });
const sessionDb = new Database(path.join(sessionsDir, 'sessions.sqlite'));
sessionDb.pragma('journal_mode = WAL');

app.use(
  session({
    name: config.session.name,
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: config.session.rollingRefresh,
    store: new SqliteStore({
      client: sessionDb,
      expired: { clear: true, intervalMs: 15 * 60 * 1000 },
    }),
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.isProd,
      maxAge: config.session.cookieMaxAgeMs,
      path: '/',
    },
  }),
);

// Attach user (and a sanitized view of them) to the request.
app.use(attachUser);

// CSRF protection — requires session middleware to be installed first.
app.use(csrfMiddleware);

// Routes.
app.get('/', (req, res) => {
  if (req.user) return res.redirect('/notes');
  return res.redirect('/login');
});

app.use('/', authRoutes);
app.use('/notes', notesRoutes);

// 404 + error handlers (must be last).
app.use(notFoundHandler);
app.use(errorHandler);

// Defensive: refuse to boot in production with insecure cookies.
if (config.isProd && !config.trustProxy && config.host !== '127.0.0.1' && config.host !== 'localhost') {
  // Production deployments must terminate TLS at a trusted proxy or bind to
  // localhost behind one. Refuse to listen on a public interface without
  // either, since Secure cookies would be unusable over plaintext HTTP.
  // eslint-disable-next-line no-console
  console.error(
    'Refusing to start: production must either set TRUST_PROXY=true (behind TLS-terminating proxy) or bind to localhost.',
  );
  process.exit(1);
}

const server = app.listen(config.port, config.host, () => {
  // eslint-disable-next-line no-console
  console.log(`Listening on http://${config.host}:${config.port} (env=${config.env})`);
});

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`Received ${signal}, shutting down...`);
  server.close(() => {
    try {
      sessionDb.close();
    } catch (_) {
      /* ignore */
    }
    process.exit(0);
  });
  // Force-exit after 10s if connections hang.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  // eslint-disable-next-line no-console
  console.error('Unhandled rejection:', reason);
});
process.on('uncaughtException', (err) => {
  // eslint-disable-next-line no-console
  console.error('Uncaught exception:', err);
  // Exit because process state may be corrupted; the supervisor should restart us.
  shutdown('uncaughtException');
});

module.exports = app;
