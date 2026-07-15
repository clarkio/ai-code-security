import path from 'node:path';
import connectPgSimple from 'connect-pg-simple';
import express, { type ErrorRequestHandler, type RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import session, { type Store } from 'express-session';
import helmet from 'helmet';
import type { Logger } from 'pino';
import type pg from 'pg';
import proxyaddr from 'proxy-addr';
import type { AppConfig } from './config.js';
import { databaseIsReady } from './db.js';
import { HttpError, notFound } from './errors.js';
import { createLogger, requestLogger } from './logger.js';
import { exposeFlash } from './middleware/auth.js';
import {
  PostgresNoteRepository,
  PostgresUserRepository,
  type NoteRepository,
  type UserRepository,
} from './repositories.js';
import { createAuthRouter } from './routes/auth.js';
import { createNotesRouter } from './routes/notes.js';
import { productionRequestGuard } from './security/headers.js';
import { csrfTokenFor } from './security/csrf.js';
import { destroySession } from './security/session-helpers.js';

const PgSessionStore = connectPgSimple(session);

export interface AppDependencies {
  readonly config: AppConfig;
  readonly pool: pg.Pool;
  readonly logger?: Logger;
  readonly sessionStore?: Store;
  readonly users?: UserRepository;
  readonly notes?: NoteRepository;
}

export function sessionCookieName(config: AppConfig): string {
  return config.isProduction ? '__Host-notes.sid' : 'notes.sid';
}

function limiter(statusMessage: string, options: Parameters<typeof rateLimit>[0]): ReturnType<typeof rateLimit> {
  return rateLimit({
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    ...options,
    handler(_request, _response, next) {
      next(new HttpError(429, statusMessage, 'RATE_LIMITED'));
    },
  });
}

function securityHeaders(config: AppConfig): RequestHandler {
  const contentSecurityPolicy = helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'none'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'"],
      objectSrc: ["'none'"],
      scriptSrc: ["'none'"],
      styleSrc: ["'self'"],
      upgradeInsecureRequests: config.isProduction ? [] : null,
    },
  });

  const baseHelmet = helmet({
    contentSecurityPolicy: false,
    strictTransportSecurity: config.isProduction
      ? { maxAge: 31_536_000, includeSubDomains: true, preload: false }
      : false,
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginEmbedderPolicy: false,
  });

  return (request, response, next) => {
    baseHelmet(request, response, (helmetError?: unknown) => {
      if (helmetError !== undefined) {
        next(helmetError);
        return;
      }
      contentSecurityPolicy(request, response, (cspError?: unknown) => {
        if (cspError !== undefined) {
          next(cspError);
          return;
        }
        response.setHeader(
          'Permissions-Policy',
          'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()',
        );
        next();
      });
    });
  };
}

function errorHandler(logger: Logger): ErrorRequestHandler {
  return (error: unknown, request, response, next) => {
    if (response.headersSent) {
      next(error);
      return;
    }

    let status = 500;
    let message = 'An unexpected error occurred.';
    let code = 'INTERNAL_ERROR';

    if (error instanceof HttpError) {
      status = error.status;
      message = error.publicMessage;
      code = error.code;
    } else if (typeof error === 'object' && error !== null && 'type' in error) {
      const errorType = (error as { type?: unknown }).type;
      if (errorType === 'entity.too.large' || errorType === 'parameters.too.many') {
        status = 413;
        message = 'The submitted form is too large.';
        code = 'BODY_TOO_LARGE';
      } else if (errorType === 'entity.parse.failed') {
        status = 400;
        message = 'The submitted form is invalid.';
        code = 'INVALID_FORM';
      } else if (errorType === 'request.aborted' || errorType === 'request.size.invalid') {
        status = 400;
        message = 'The submitted request is invalid.';
        code = 'INVALID_REQUEST';
      } else if (errorType === 'charset.unsupported' || errorType === 'encoding.unsupported') {
        status = 415;
        message = 'The form encoding is not supported.';
        code = 'UNSUPPORTED_ENCODING';
      }
    }

    if (status >= 500) {
      logger.error(
        {
          requestId: request.id,
          errorType: error instanceof Error ? error.name : typeof error,
        },
        'Request failed',
      );
    }

    response.status(status).render('error', {
      title: status === 404 ? 'Not found' : 'Request failed',
      status,
      message,
      code,
      requestId: request.id,
    });
  };
}

export function createApp(dependencies: AppDependencies): express.Express {
  const { config, pool } = dependencies;
  const logger = dependencies.logger ?? createLogger(config.logLevel);
  const users = dependencies.users ?? new PostgresUserRepository(pool);
  const notes = dependencies.notes ?? new PostgresNoteRepository(pool, config.maxNotesPerUser);
  const store =
    dependencies.sessionStore ??
    new PgSessionStore({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: false,
      pruneSessionInterval: 15 * 60,
    });

  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.set('case sensitive routing', true);
  app.set('strict routing', true);
  app.set('query parser', false);
  app.set('view engine', 'ejs');
  app.set('views', path.join(process.cwd(), 'src', 'views'));
  app.set('view cache', config.isProduction);
  if (config.trustProxyHops > 0) {
    const isTrustedAddress = proxyaddr.compile([...config.trustedProxyCidrs]);
    app.set(
      'trust proxy',
      (address: string, hop: number) =>
        hop < config.trustProxyHops && isTrustedAddress(address, hop),
    );
  }

  app.use((_request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    response.locals['isAuthenticated'] = false;
    response.locals['csrfToken'] = '';
    response.locals['flash'] = undefined;
    next();
  });
  app.use(requestLogger(logger));
  app.use(securityHeaders(config));
  app.use(productionRequestGuard(config));

  app.get('/health/live', (_request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.status(200).type('text/plain').send('ok');
  });
  app.get('/health/ready', async (_request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    try {
      const ready = await databaseIsReady(pool);
      response.status(ready ? 200 : 503).type('text/plain').send(ready ? 'ready' : 'unavailable');
    } catch {
      response.status(503).type('text/plain').send('unavailable');
    }
  });

  app.use(
    limiter('Too many requests. Please try again later.', {
      windowMs: 15 * 60_000,
      limit: 300,
    }),
  );

  app.use(
    '/assets',
    express.static(path.join(process.cwd(), 'public'), {
      dotfiles: 'deny',
      etag: true,
      fallthrough: true,
      index: false,
      maxAge: config.isProduction ? '1h' : 0,
    }),
  );

  app.use(
    express.urlencoded({
      extended: false,
      inflate: false,
      limit: '36kb',
      parameterLimit: 10,
    }),
  );
  app.use(
    session({
      name: sessionCookieName(config),
      secret: [...config.sessionSecrets],
      store,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      unset: 'destroy',
      cookie: {
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'strict',
        path: '/',
        maxAge: config.sessionTtlMs,
        priority: 'high',
      },
    }),
  );

  app.use(async (request, response, next) => {
    if (request.session.userId === undefined) {
      next();
      return;
    }

    const authenticatedAt = request.session.authenticatedAt;
    const sessionIsCurrent =
      typeof authenticatedAt === 'number' &&
      Number.isSafeInteger(authenticatedAt) &&
      authenticatedAt <= Date.now() &&
      Date.now() - authenticatedAt <= config.sessionTtlMs;

    if (sessionIsCurrent) {
      next();
      return;
    }

    try {
      await destroySession(request);
      response.clearCookie(sessionCookieName(config), {
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'strict',
        path: '/',
      });
      response.redirect(303, '/login');
    } catch (error) {
      next(error);
    }
  });

  app.use((request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    response.locals['isAuthenticated'] = request.session.userId !== undefined;
    if (request.session.userId !== undefined) {
      response.locals['csrfToken'] = csrfTokenFor(request);
    }
    next();
  });
  app.use(exposeFlash);

  const authRateLimit = limiter('Too many authentication attempts. Please try again later.', {
    windowMs: 15 * 60_000,
    limit: 10,
  });
  const writeRateLimit = limiter('Too many changes. Please try again later.', {
    windowMs: 15 * 60_000,
    limit: 60,
    keyGenerator: (request) =>
      request.session.userId ?? ipKeyGenerator(request.ip ?? request.socket.remoteAddress ?? 'unknown'),
  });

  app.get('/', (request, response) => {
    response.redirect(303, request.session.userId === undefined ? '/login' : '/notes');
  });
  app.use(
    createAuthRouter({
      config,
      users,
      authRateLimit,
      sessionCookieName: sessionCookieName(config),
    }),
  );
  app.use(createNotesRouter({ config, notes, writeRateLimit }));

  app.use((_request, _response, next) => next(notFound()));
  app.use(errorHandler(logger));

  return app;
}
