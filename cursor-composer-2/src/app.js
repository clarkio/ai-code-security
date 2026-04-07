import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import expressLayouts from 'express-ejs-layouts';

import { config } from './config.js';
import { authRouter } from './routes/auth.js';
import { notesRouter } from './routes/notes.js';
import { ensureCsrfToken } from './lib/csrf.js';
import { csrfProtection } from './middleware/csrf.js';
import { errorHandler } from './middleware/errors.js';

const FileStore = FileStoreFactory(session);

export function createApp() {
  const app = express();

  if (config.trustProxy) {
    app.set('trust proxy', 1);
  }

  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'"],
          fontSrc: ["'self'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
          ...(config.isProd ? { upgradeInsecureRequests: [] } : {}),
        },
      },
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    })
  );

  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(globalLimiter);

  app.use(
    express.urlencoded({
      extended: false,
      limit: '256kb',
      parameterLimit: 50,
    })
  );

  fs.mkdirSync(config.sessionFilesDir, { recursive: true });

  app.use(
    session({
      store: new FileStore({
        path: config.sessionFilesDir,
        ttl: 7 * 24 * 60 * 60,
        retries: 1,
        logFn: () => {},
      }),
      name: config.sessionCookieName,
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: config.isProd,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/',
      },
    })
  );

  app.use((req, res, next) => {
    res.locals.currentUser = Boolean(req.session?.userId);
    res.locals.csrfToken = ensureCsrfToken(req);
    next();
  });

  app.use(csrfProtection);

  app.set('views', path.join(config.rootDir, 'views'));
  app.set('view engine', 'ejs');
  app.use(expressLayouts);
  app.set('layout', 'layout');

  app.use(
    '/static',
    express.static(path.join(config.rootDir, 'public'), {
      index: false,
      dotfiles: 'deny',
      maxAge: config.isProd ? '1d' : 0,
    })
  );

  app.get('/', (req, res) => {
    if (req.session?.userId) {
      return res.redirect('/notes');
    }
    res.redirect('/login');
  });

  app.use('/', authRouter);
  app.use('/notes', notesRouter);

  app.use((req, res) => {
    res.status(404).type('html').send('<!DOCTYPE html><title>Not found</title><p>Not found</p>');
  });

  app.use(errorHandler);

  return app;
}
