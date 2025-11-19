const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const hpp = require('hpp');
const morgan = require('morgan');
const { migrate, run, get, all } = require('./db');
const config = require('./config');
const { attachUser, requireAuth } = require('./middleware/auth');
const { registerSchema, loginSchema, noteSchema } = require('./validators');

const app = express();
app.disable('x-powered-by');

const sessionDbPath = config.env === 'test' ? path.join(__dirname, '..', 'data', 'sessions-test.db') : path.join(__dirname, '..', 'data', 'sessions.db');

const commonLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please slow down.' },
});

const sessionOptions = {
  name: 'sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.secureCookies,
    maxAge: 1000 * 60 * 60 * 24, // 1 day
  },
};

if (config.env === 'test') {
  sessionOptions.store = new session.MemoryStore();
} else {
  if (!fs.existsSync(path.dirname(sessionDbPath))) {
    fs.mkdirSync(path.dirname(sessionDbPath), { recursive: true });
  }
  sessionOptions.store = new SQLiteStore({
    db: path.basename(sessionDbPath),
    dir: path.dirname(sessionDbPath),
    table: 'sessions',
  });
}

if (config.trustProxy) {
  app.set('trust proxy', 1);
}

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
  })
);
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(hpp());
app.use(commonLimiter);

if (config.env !== 'test') {
  app.use(morgan('common'));
}

app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

app.use(session(sessionOptions));

const csrfProtection = csrf();

app.use(attachUser);

app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post('/auth/register', authLimiter, csrfProtection, async (req, res, next) => {
  try {
    if (!config.allowRegistration) {
      return res.status(403).json({ error: 'User registration is disabled' });
    }
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }

    const existing = await get('SELECT id FROM users WHERE username = ?', [value.username]);
    if (existing) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(value.password, 12);
    const now = Date.now();
    const result = await run(
      'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
      [value.username, passwordHash, now]
    );

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = result.lastID;
      req.session.username = value.username;
      res.status(201).json({ id: result.lastID, username: value.username, createdAt: now });
    });
  } catch (err) {
    return next(err);
  }
});

app.post('/auth/login', authLimiter, csrfProtection, async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }

    const user = await get('SELECT id, username, password_hash FROM users WHERE username = ?', [
      value.username,
    ]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(value.password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      res.json({ id: user.id, username: user.username });
    });
  } catch (err) {
    return next(err);
  }
});

app.post('/auth/logout', csrfProtection, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid', {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.secureCookies,
    });
    res.json({ success: true });
  });
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

app.get('/notes', requireAuth, async (req, res, next) => {
  try {
    const notes = await all(
      'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC',
      [req.user.id]
    );
    res.json({ notes });
  } catch (err) {
    return next(err);
  }
});

app.post('/notes', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const { error, value } = noteSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }
    const now = Date.now();
    const result = await run(
      'INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, value.title, value.content, now, now]
    );
    res.status(201).json({ id: result.lastID, title: value.title, content: value.content, createdAt: now, updatedAt: now });
  } catch (err) {
    return next(err);
  }
});

app.put('/notes/:id', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const { error, value } = noteSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }
    const now = Date.now();
    const result = await run(
      'UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?',
      [value.title, value.content, now, req.params.id, req.user.id]
    );
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }
    res.json({ id: Number(req.params.id), title: value.title, content: value.content, updatedAt: now });
  } catch (err) {
    return next(err);
  }
});

app.delete('/notes/:id', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const result = await run('DELETE FROM notes WHERE id = ? AND user_id = ?', [
      req.params.id,
      req.user.id,
    ]);
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }
    res.json({ success: true });
  } catch (err) {
    return next(err);
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Malformed request body' });
  }
  console.error(err);
  return res.status(500).json({ error: 'Internal server error' });
});

const start = async () => {
  await migrate();

  if (config.adminPassword) {
    const existing = await get('SELECT id FROM users WHERE username = ?', [config.adminUsername]);
    if (!existing) {
      const passwordHash = await bcrypt.hash(config.adminPassword, 12);
      await run('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)', [
        config.adminUsername,
        passwordHash,
        Date.now(),
      ]);
      console.log(`Provisioned admin user "${config.adminUsername}".`);
    }
  }

  app.listen(config.port, () => {
    console.log(`Secure notes service running on port ${config.port}`);
  });
};

if (require.main === module) {
  start().catch((err) => {
    console.error('Failed to start server', err);
    process.exit(1);
  });
}

module.exports = app;
