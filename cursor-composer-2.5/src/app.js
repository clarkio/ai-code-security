import cookieParser from 'cookie-parser';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import hpp from 'hpp';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { attachUser } from './middleware/auth.js';
import {
  doubleCsrfProtection,
  ensureCsrfSession,
  injectCsrfToken,
} from './middleware/csrf.js';
import { consumeFlash } from './middleware/flash.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { globalLimiter } from './middleware/rateLimit.js';
import authRoutes from './routes/auth.js';
import notesRoutes from './routes/notes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

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
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(hpp());
  app.use(globalLimiter);

  app.set('view engine', 'ejs');
  app.set('views', join(__dirname, '..', 'views'));

  app.use(express.static(join(__dirname, '..', 'public'), {
    maxAge: config.isProduction ? '1d' : 0,
    dotfiles: 'deny',
  }));

  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.use(cookieParser());

  app.use(
    session({
      name: 'sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'strict',
        maxAge: config.sessionMaxAgeMs,
        path: '/',
      },
    })
  );

  app.use(ensureCsrfSession);
  app.use(consumeFlash);
  app.use(attachUser);
  app.use(injectCsrfToken);
  app.use(doubleCsrfProtection);

  app.get('/', (req, res) => {
    if (req.session.userId) {
      return res.redirect('/notes');
    }
    res.redirect('/login');
  });

  app.use(authRoutes);
  app.use('/notes', notesRoutes);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
