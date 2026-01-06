import { doubleCsrf } from 'csrf-csrf';
import type { RequestHandler } from 'express';
import { config } from '../config';

const csrf = doubleCsrf({
  getSecret: () => config.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.csrfSid ?? '',
  cookieName: config.COOKIE_SECURE ? '__Host-csrf' : 'csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.COOKIE_SECURE,
    path: '/',
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req: { body?: unknown; headers: Record<string, unknown> }) => {
    const bodyToken = (req.body as Record<string, unknown> | undefined)?._csrf;
    const headerToken = req.headers['x-csrf-token'];
    if (typeof bodyToken === 'string') return bodyToken;
    if (typeof headerToken === 'string') return headerToken;
    return '';
  },
});

export const csrfProtection: RequestHandler = csrf.doubleCsrfProtection;

export const csrfTokenLocals: RequestHandler = (req, res, next) => {
  res.locals.csrfToken = csrf.generateCsrfToken(req, res);
  next();
};
