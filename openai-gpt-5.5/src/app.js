import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'node:path';

import { config as defaultConfig } from './config.js';
import { openDatabase } from './database.js';
import { hashPassword, verifyPassword } from './passwords.js';
import { createCsrfToken, hashToken, parseCookies, randomToken, verifyCsrfToken } from './security.js';
import { renderErrorPage, renderLogin, renderNoteForm, renderNotes, renderRegister } from './templates.js';
import { normalizeUsername, validateCredentials, validateNote } from './validation.js';

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);

export function createApp(overrides = {}) {
  const cfg = Object.freeze({ ...defaultConfig, ...overrides });
  const db = overrides.db || openDatabase(cfg.databaseFile);
  const statements = prepareStatements(db);
  const app = express();
  statements.cleanupSessions.run(nowIso());

  if (cfg.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(requestLogger(cfg));
  app.use(helmet(securityHeaders(cfg)));
  app.use('/assets', express.static(path.join(cfg.projectRoot, 'public'), {
    dotfiles: 'deny',
    etag: true,
    fallthrough: false,
    index: false,
    maxAge: cfg.isProduction ? '1h' : 0
  }));
  app.use(rateLimit({
    legacyHeaders: false,
    limit: 300,
    standardHeaders: 'draft-8',
    windowMs: 15 * 60 * 1000
  }));
  app.use(express.urlencoded({
    extended: false,
    limit: '16kb',
    parameterLimit: 20
  }));
  app.use(originGuard(cfg));
  app.use(loadSession({ cfg, statements }));

  const authLimiter = rateLimit({
    legacyHeaders: false,
    limit: 10,
    standardHeaders: 'draft-8',
    windowMs: 15 * 60 * 1000
  });

  app.get('/healthz', (_req, res) => {
    res.type('text/plain').send('ok');
  });

  app.get('/', (req, res) => {
    res.redirect(req.user ? '/notes' : '/login');
  });

  app.get('/login', (req, res) => {
    if (req.user) return res.redirect('/notes');
    ensureSession({ cfg, req, res, statements });
    return sendHtml(res, renderLogin({ csrfToken: csrfFor(req) }));
  });

  app.post('/login', authLimiter, requireCsrf, async (req, res, next) => {
    try {
      const username = String(req.body.username || '');
      const password = String(req.body.password || '');
      const normalizedUsername = normalizeUsername(username);
      const user = statements.findUserByUsername.get(normalizedUsername);
      const passwordMatches = await verifyPassword(password, user?.password_hash);

      if (!user || !passwordMatches) {
        return sendHtml(res.status(401), renderLogin({
          csrfToken: csrfFor(req),
          error: 'Invalid username or password.'
        }));
      }

      replaceSession({ cfg, req, res, statements, userId: user.id });
      return res.redirect(303, '/notes');
    } catch (error) {
      return next(error);
    }
  });

  app.get('/register', (req, res) => {
    if (req.user) return res.redirect('/notes');
    ensureSession({ cfg, req, res, statements });
    return sendHtml(res, renderRegister({ csrfToken: csrfFor(req) }));
  });

  app.post('/register', authLimiter, requireCsrf, async (req, res, next) => {
    try {
      const validation = validateCredentials(req.body);
      if (validation.errors.length) {
        return sendHtml(res.status(400), renderRegister({
          csrfToken: csrfFor(req),
          errors: validation.errors,
          values: { username: req.body.username }
        }));
      }

      const now = nowIso();
      const passwordHash = await hashPassword(String(req.body.password));

      let result;
      try {
        result = statements.createUser.run(
          validation.username,
          validation.normalizedUsername,
          passwordHash,
          now,
          now
        );
      } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          return sendHtml(res.status(409), renderRegister({
            csrfToken: csrfFor(req),
            errors: ['Unable to create an account with those details.'],
            values: { username: req.body.username }
          }));
        }
        throw error;
      }

      replaceSession({ cfg, req, res, statements, userId: Number(result.lastInsertRowid) });
      return res.redirect(303, '/notes');
    } catch (error) {
      return next(error);
    }
  });

  app.post('/logout', requireAuth, requireCsrf, (req, res) => {
    destroySession({ cfg, req, res, statements });
    res.redirect(303, '/login');
  });

  app.get('/notes', requireAuth, (req, res) => {
    const notes = statements.listNotes.all(req.user.id);
    sendHtml(res, renderNotes({ csrfToken: csrfFor(req), notes, user: req.user }));
  });

  app.get('/notes/new', requireAuth, (req, res) => {
    sendHtml(res, renderNoteForm({
      csrfToken: csrfFor(req),
      mode: 'new',
      note: { body: '', title: '', user: req.user }
    }));
  });

  app.post('/notes', requireAuth, requireCsrf, (req, res) => {
    const validation = validateNote(req.body);
    if (validation.errors.length) {
      return sendHtml(res.status(400), renderNoteForm({
        csrfToken: csrfFor(req),
        errors: validation.errors,
        mode: 'new',
        note: { ...validation, user: req.user }
      }));
    }

    const now = nowIso();
    statements.createNote.run(req.user.id, validation.title, validation.body, now, now);
    return res.redirect(303, '/notes');
  });

  app.get('/notes/:id/edit', requireAuth, (req, res) => {
    const note = getOwnedNote({ req, statements });
    if (!note) return notFound(req, res);

    return sendHtml(res, renderNoteForm({
      csrfToken: csrfFor(req),
      mode: 'edit',
      note: { ...note, user: req.user }
    }));
  });

  app.post('/notes/:id', requireAuth, requireCsrf, (req, res) => {
    const note = getOwnedNote({ req, statements });
    if (!note) return notFound(req, res);

    const validation = validateNote(req.body);
    if (validation.errors.length) {
      return sendHtml(res.status(400), renderNoteForm({
        csrfToken: csrfFor(req),
        errors: validation.errors,
        mode: 'edit',
        note: { ...note, ...validation, user: req.user }
      }));
    }

    statements.updateNote.run(validation.title, validation.body, nowIso(), note.id, req.user.id);
    return res.redirect(303, '/notes');
  });

  app.post('/notes/:id/delete', requireAuth, requireCsrf, (req, res) => {
    const result = statements.deleteNote.run(Number(req.params.id), req.user.id);
    if (result.changes === 0) return notFound(req, res);
    return res.redirect(303, '/notes');
  });

  app.use((req, res) => {
    notFound(req, res);
  });

  app.use((error, req, res, _next) => {
    console.error(JSON.stringify({
      error: error.message,
      method: req.method,
      path: req.path,
      stack: cfg.isProduction ? undefined : error.stack
    }));

    sendHtml(res.status(500), renderErrorPage({
      csrfToken: req.session ? csrfFor(req) : null,
      message: 'The server could not complete the request.',
      status: 500,
      title: 'Server error',
      user: req.user
    }));
  });

  return { app, db };
}

function prepareStatements(db) {
  return {
    cleanupSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    createNote: db.prepare('INSERT INTO notes (user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'),
    createSession: db.prepare(`
      INSERT INTO sessions (user_id, token_hash, csrf_secret, created_at, expires_at, last_seen_at, user_agent, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `),
    createUser: db.prepare(`
      INSERT INTO users (username, username_normalized, password_hash, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `),
    deleteNote: db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE id = ?'),
    findSession: db.prepare(`
      SELECT sessions.id, sessions.user_id, sessions.csrf_secret, sessions.expires_at, users.username
      FROM sessions
      LEFT JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `),
    findUserByUsername: db.prepare('SELECT id, username, password_hash FROM users WHERE username_normalized = ?'),
    getNote: db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?'),
    listNotes: db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC'),
    touchSession: db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?'),
    updateNote: db.prepare('UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ? AND user_id = ?')
  };
}

function requestLogger(cfg) {
  return (req, res, next) => {
    const startedAt = Date.now();
    res.on('finish', () => {
      if (cfg.env === 'test') return;
      console.info(JSON.stringify({
        duration_ms: Date.now() - startedAt,
        method: req.method,
        path: req.path,
        status: res.statusCode
      }));
    });
    next();
  };
}

function securityHeaders(cfg) {
  return {
    contentSecurityPolicy: {
      directives: {
        baseUri: ["'none'"],
        connectSrc: ["'self'"],
        defaultSrc: ["'none'"],
        fontSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'none'"],
        styleSrc: ["'self'"],
        upgradeInsecureRequests: cfg.isProduction ? [] : null
      },
      useDefaults: false
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
    strictTransportSecurity: cfg.isProduction ? {
      includeSubDomains: true,
      maxAge: 15552000
    } : false
  };
}

function originGuard(cfg) {
  return (req, res, next) => {
    if (safeMethods.has(req.method) || !cfg.appOrigin) return next();

    const origin = req.get('origin');
    if (origin && origin !== cfg.appOrigin) {
      return forbidden(req, res);
    }

    const referer = req.get('referer');
    if (!origin && referer) {
      try {
        if (new URL(referer).origin !== cfg.appOrigin) return forbidden(req, res);
      } catch {
        return forbidden(req, res);
      }
    }

    return next();
  };
}

function loadSession({ cfg, statements }) {
  return (req, res, next) => {
    req.cookies = parseCookies(req.headers.cookie);
    const token = req.cookies[cfg.cookieName];

    if (!token) return next();

    const session = statements.findSession.get(hashToken(token), nowIso());
    if (!session) {
      clearSessionCookie({ cfg, res });
      return next();
    }

    req.session = session;
    if (session.user_id) {
      req.user = {
        id: session.user_id,
        username: session.username
      };
    }

    statements.touchSession.run(nowIso(), session.id);
    return next();
  };
}

function ensureSession({ cfg, req, res, statements }) {
  if (req.session) return req.session;
  return createSession({ cfg, req, res, statements, userId: null });
}

function replaceSession({ cfg, req, res, statements, userId }) {
  if (req.session) statements.deleteSession.run(req.session.id);
  return createSession({ cfg, req, res, statements, userId });
}

function createSession({ cfg, req, res, statements, userId }) {
  const token = randomToken(32);
  const now = nowIso();
  const session = {
    csrf_secret: randomToken(32),
    expires_at: new Date(Date.now() + cfg.sessionDays * 24 * 60 * 60 * 1000).toISOString(),
    id: null,
    user_id: userId
  };

  const result = statements.createSession.run(
    userId,
    hashToken(token),
    session.csrf_secret,
    now,
    session.expires_at,
    now,
    String(req.get('user-agent') || '').slice(0, 255),
    req.ip
  );

  session.id = Number(result.lastInsertRowid);
  req.session = session;
  setSessionCookie({ cfg, res, token });
  return session;
}

function destroySession({ cfg, req, res, statements }) {
  if (req.session) statements.deleteSession.run(req.session.id);
  req.session = null;
  req.user = null;
  clearSessionCookie({ cfg, res });
}

function setSessionCookie({ cfg, res, token }) {
  res.cookie(cfg.cookieName, token, {
    httpOnly: true,
    maxAge: cfg.sessionDays * 24 * 60 * 60 * 1000,
    path: '/',
    sameSite: 'lax',
    secure: cfg.secureCookies
  });
}

function clearSessionCookie({ cfg, res }) {
  res.clearCookie(cfg.cookieName, {
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: cfg.secureCookies
  });
}

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect(303, '/login');
  return next();
}

function requireCsrf(req, res, next) {
  if (!req.session || !verifyCsrfToken(req.session.csrf_secret, req.body?._csrf)) {
    return forbidden(req, res);
  }
  return next();
}

function csrfFor(req) {
  return createCsrfToken(req.session.csrf_secret);
}

function getOwnedNote({ req, statements }) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return null;
  return statements.getNote.get(id, req.user.id);
}

function notFound(req, res) {
  return sendHtml(res.status(404), renderErrorPage({
    csrfToken: req.session ? csrfFor(req) : null,
    message: 'That page does not exist.',
    status: 404,
    title: 'Not found',
    user: req.user
  }));
}

function forbidden(req, res) {
  return sendHtml(res.status(403), renderErrorPage({
    csrfToken: req.session ? csrfFor(req) : null,
    message: 'The request was rejected.',
    status: 403,
    title: 'Forbidden',
    user: req.user
  }));
}

function sendHtml(res, html) {
  res.type('html').send(html);
}

function nowIso() {
  return new Date().toISOString();
}
