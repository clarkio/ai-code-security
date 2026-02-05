const crypto = require('crypto');
const path = require('path');
const express = require('express');
const { engine } = require('express-handlebars');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

function createApp() {
  const app = express();

  // --- Trust proxy if behind a reverse proxy (Nginx, load balancer) ---
  app.set('trust proxy', 1);

  // --- Handlebars template engine (auto-escapes by default) ---
  app.engine(
    'hbs',
    engine({
      extname: '.hbs',
      defaultLayout: 'main',
      layoutsDir: path.join(__dirname, 'views', 'layouts'),
    })
  );
  app.set('view engine', 'hbs');
  app.set('views', path.join(__dirname, 'views'));

  // --- Security headers via Helmet ---
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
    })
  );

  // --- Body parsing with size limits ---
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));

  // --- Session configuration ---
  const isProduction = process.env.NODE_ENV === 'production';

  app.use(
    session({
      store: new FileStore({
        path: path.join(__dirname, '..', 'sessions'),
        ttl: 7200, // 2 hours in seconds
        retries: 0,
        reapInterval: 600, // cleanup every 10 minutes
      }),
      secret: process.env.SESSION_SECRET,
      name: '__sid',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 2, // 2 hours
      },
    })
  );

  // --- CSRF protection (synchronizer token pattern) ---
  function csrfGenerate(req, res, next) {
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
  }

  function csrfVerify(req, res, next) {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      const token = req.body._csrf;
      if (
        !token ||
        !req.session.csrfToken ||
        !crypto.timingSafeEqual(
          Buffer.from(token, 'utf8'),
          Buffer.from(req.session.csrfToken, 'utf8')
        )
      ) {
        return res.status(403).send('Invalid or missing CSRF token');
      }
    }
    next();
  }

  app.use(csrfGenerate);
  app.use(csrfVerify);

  // --- Rate limiting ---
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many attempts, please try again later.',
  });

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use(generalLimiter);

  // --- Make session user available to all templates ---
  app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { id: req.session.userId } : null;
    next();
  });

  // --- Routes ---
  app.use('/', authRoutes(authLimiter));
  app.use('/', notesRoutes);

  // --- 404 handler ---
  app.use((req, res) => {
    res.status(404).send('Page not found');
  });

  // --- Error handler (never leak stack traces) ---
  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).send('An unexpected error occurred');
  });

  return app;
}

module.exports = createApp;
