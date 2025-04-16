// app.js - Secure Notes App
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const bcrypt = require('bcrypt');
const xss = require('xss-clean');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Security: HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https:'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    }
  }
}));

// Security: Rate limiting
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100, // limit each IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Security: Body parsing and XSS-clean
app.use(express.urlencoded({ extended: false }));
app.use(xss());

// Sessions
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// CSRF protection
app.use(csrf());

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to pass user and csrfToken to views
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Helper: Require login
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// Routes
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.all('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC', [req.session.user.id], (err, notes) => {
    if (err) return res.status(500).render('error', { message: 'Database error.' });
    res.render('index', { notes });
  });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 3 || password.length < 8) {
    return res.render('register', { error: 'Username and password required. Password must be at least 8 characters.' });
  }
  db.get('SELECT id FROM users WHERE username = ?', [username], async (err, user) => {
    if (user) return res.render('register', { error: 'Username already exists.' });
    const hash = await bcrypt.hash(password, 12);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
      if (err) return res.render('register', { error: 'Registration failed.' });
      req.session.user = { id: this.lastID, username };
      res.redirect('/');
    });
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.render('login', { error: 'Invalid credentials.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error: 'Invalid credentials.' });
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/');
  });
});

app.post('/logout', requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Note CRUD
app.post('/notes', requireLogin, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content || title.length > 100 || content.length > 1000) {
    return res.status(400).render('error', { message: 'Invalid note data.' });
  }
  db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', [req.session.user.id, title, content], function(err) {
    if (err) return res.status(500).render('error', { message: 'Failed to create note.' });
    res.redirect('/');
  });
});

app.post('/notes/:id/update', requireLogin, (req, res) => {
  const { title, content } = req.body;
  const noteId = req.params.id;
  if (!title || !content || title.length > 100 || content.length > 1000) {
    return res.status(400).render('error', { message: 'Invalid note data.' });
  }
  db.run('UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?', [title, content, noteId, req.session.user.id], function(err) {
    if (err || this.changes === 0) return res.status(403).render('error', { message: 'Update failed or unauthorized.' });
    res.redirect('/');
  });
});

app.post('/notes/:id/delete', requireLogin, (req, res) => {
  const noteId = req.params.id;
  db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [noteId, req.session.user.id], function(err) {
    if (err || this.changes === 0) return res.status(403).render('error', { message: 'Delete failed or unauthorized.' });
    res.redirect('/');
  });
});

// Error handling
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', { message: 'Invalid CSRF token.' });
  }
  res.status(500).render('error', { message: 'An unexpected error occurred.' });
});

// Production: Enforce HTTPS
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Secure Notes App running on port ${PORT}`);
});
