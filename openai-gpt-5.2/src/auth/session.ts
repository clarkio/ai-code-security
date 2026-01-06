import type { RequestHandler } from 'express';
import createError from 'http-errors';
import { getIronSession, type SessionOptions } from 'iron-session';
import { config } from '../config';

export type SessionUser = {
  id: string;
  email: string;
};

export type SessionData = {
  user?: SessionUser;
  csrfSid?: string;
};

export const sessionOptions: SessionOptions = {
  cookieName: config.COOKIE_SECURE ? '__Host-notes' : 'notes',
  password: config.SESSION_PASSWORD,
  cookieOptions: {
    httpOnly: true,
    secure: config.COOKIE_SECURE,
    sameSite: 'lax',
    path: '/',
  },
  ttl: 60 * 60 * 24 * 7,
};

export const sessionMiddleware: RequestHandler = async (req, res, next) => {
  try {
    req.session = await getIronSession<SessionData>(req, res, sessionOptions);
    return next();
  } catch (err) {
    return next(err);
  }
};

export const requireUser: RequestHandler = (req, _res, next) => {
  if (!req.session.user) {
    return next(createError(401));
  }
  return next();
};
