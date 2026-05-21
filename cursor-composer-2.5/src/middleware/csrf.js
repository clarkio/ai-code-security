import { doubleCsrf } from 'csrf-csrf';
import { config } from '../config.js';

const csrfCookieName = config.isProduction ? '__Host-csrf' : 'csrf-token';

const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => config.sessionSecret,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'strict',
    path: '/',
  },
  getSessionIdentifier: (req) => req.session?.csrfSessionId ?? '',
  getTokenFromRequest: (req) =>
    req.body?._csrf ?? req.headers['x-csrf-token'],
  size: 64,
});

export function ensureCsrfSession(req, res, next) {
  if (!req.session.csrfSessionId) {
    req.session.csrfSessionId = crypto.randomUUID();
  }
  next();
}

export function injectCsrfToken(req, res, next) {
  res.locals.csrfToken = generateToken(req, res);
  next();
}

export { doubleCsrfProtection };
