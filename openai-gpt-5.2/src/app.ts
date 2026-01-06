import express from 'express';
import cookieParser from 'cookie-parser';
import createError from 'http-errors';
import pinoHttp from 'pino-http';
import expressLayouts from 'express-ejs-layouts';
import crypto from 'crypto';

import { config, isProd } from './config';
import { logger } from './logger';
import { sessionMiddleware } from './auth/session';
import { helmetMiddleware } from './security/helmet';
import { httpsRedirectMiddleware } from './security/httpsRedirect';
import { globalRateLimit } from './security/rateLimit';
import { csrfProtection, csrfTokenLocals } from './security/csrf';

import authRoutes from './routes/auth';
import notesRoutes from './routes/notes';

export function createApp() {
  const app = express();

  if (config.TRUST_PROXY) {
    app.set('trust proxy', 1);
  }

  app.disable('x-powered-by');

  app.use(pinoHttp({ logger }));
  app.use(httpsRedirectMiddleware());
  app.use(helmetMiddleware());
  app.use(globalRateLimit);

  app.use('/static', express.static('public', { fallthrough: false }));

  app.set('view engine', 'ejs');
  app.set('views', 'views');
  app.use(expressLayouts);
  app.set('layout', 'layout');

  app.use(express.urlencoded({ extended: false, limit: '10kb' }));

  // Used by csrf-csrf cookie setting.
  app.use(cookieParser(config.CSRF_SECRET));

  app.use(sessionMiddleware);

  app.use(async (req, _res, next) => {
    try {
      if (!req.session.csrfSid) {
        req.session.csrfSid = crypto.randomBytes(16).toString('hex');
        await req.session.save();
      }
      return next();
    } catch (err) {
      return next(err);
    }
  });

  // CSRF protection (all non-GET/HEAD/OPTIONS)
  app.use(csrfProtection);

  // Common locals for views
  app.use((req, res, next) => {
    res.locals.user = req.session.user ?? null;
    res.locals.title = 'Secure Notes';
    res.locals.error = null;
    next();
  });
  app.use(csrfTokenLocals);

  app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/notes');
    return res.redirect('/login');
  });

  app.use(authRoutes);
  app.use(notesRoutes);

  app.use((_req, _res, next) => {
    next(createError(404));
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = (err as { status?: number }).status ?? 500;

    if (!isProd) {
      logger.error({ err }, 'request error');
    }

    if (status === 401) {
      return res.status(401).redirect('/login');
    }

    if (status === 404) {
      return res.status(404).send('Not Found');
    }

    return res.status(500).send('Internal Server Error');
  });

  return app;
}
