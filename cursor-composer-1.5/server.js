/**
 * Secure Notes Application - Production-ready server
 */
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import csrf from 'csurf';
import expressLayouts from 'express-ejs-layouts';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { config } from './config.js';
import { initDb } from './db/index.js';
import { helmetMiddleware, rateLimitMiddleware } from './middleware/security.js';
import authRoutes from './routes/auth.js';
import notesRoutes from './routes/notes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

await initDb();

const app = express();

// Security middleware (order matters)
app.use(helmetMiddleware);
app.use(rateLimitMiddleware);

// Body parsing
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use(cookieParser());

// Session - must be before CSRF
const sessionConfig = {
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  name: 'notes.sid',
  cookie: {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
  },
};
app.use(session(sessionConfig));

// CSRF protection - after session
app.use(csrf({ cookie: false }));

// View engine
app.set('view engine', 'ejs');
app.set('views', join(__dirname, 'views'));
app.use(expressLayouts);

// Locals for templates
app.use((req, res, next) => {
  res.locals.user = req.session?.userId
    ? { id: req.session.userId, username: req.session.username }
    : null;
  next();
});

// Routes
app.get('/', (req, res) => {
  if (req.session?.userId) {
    return res.redirect('/notes');
  }
  res.redirect('/login');
});

app.use('/', authRoutes);
app.use('/notes', notesRoutes);

// 404
app.use((req, res) => {
  res.status(404).render('error', { message: 'Page not found' });
});

// Error handler - never leak stack traces in production
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', { message: 'Invalid request. Please try again.' });
  }
  console.error(err);
  res.status(500).render('error', {
    message: config.isProduction ? 'An error occurred.' : err.message,
  });
});

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port} (${config.env})`);
}).on('error', (err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
