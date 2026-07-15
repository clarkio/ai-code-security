import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { HttpError } from '../errors.js';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export function csrfTokenFor(request: Request): string {
  if (request.session.csrfToken === undefined) {
    request.session.csrfToken = randomBytes(32).toString('base64url');
  }
  return request.session.csrfToken;
}

export function exposeCsrfToken(request: Request, response: Response, next: NextFunction): void {
  response.locals['csrfToken'] = csrfTokenFor(request);
  next();
}

function currentRequestOrigin(request: Request): string | undefined {
  const host = request.get('host');
  if (host === undefined) return undefined;
  try {
    return new URL(`${request.protocol}://${host}`).origin;
  } catch {
    return undefined;
  }
}

export function createCsrfProtection(publicOrigin: string, allowCurrentRequestOrigin: boolean) {
  return (request: Request, response: Response, next: NextFunction): void => {
    if (!request.is('application/x-www-form-urlencoded')) {
      next(new HttpError(415, 'This endpoint accepts HTML form submissions only.', 'UNSUPPORTED_MEDIA_TYPE'));
      return;
    }

    const fetchSite = request.get('sec-fetch-site');
    if (fetchSite === 'cross-site') {
      next(new HttpError(403, 'The security token is invalid or expired.', 'CSRF_REJECTED'));
      return;
    }

    const origin = request.get('origin');
    const originIsAllowed =
      origin === undefined ||
      origin === publicOrigin ||
      (allowCurrentRequestOrigin && origin === currentRequestOrigin(request));
    if (!originIsAllowed) {
      next(new HttpError(403, 'The security token is invalid or expired.', 'CSRF_REJECTED'));
      return;
    }

    const body = request.body as unknown;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      next(new HttpError(403, 'The security token is invalid or expired.', 'CSRF_REJECTED'));
      return;
    }

    const submitted = (body as Record<string, unknown>)['_csrf'];
    const expected = request.session.csrfToken;
    const valid =
      typeof submitted === 'string' &&
      TOKEN_PATTERN.test(submitted) &&
      typeof expected === 'string' &&
      timingSafeEqual(digest(submitted), digest(expected));

    if (!valid) {
      next(new HttpError(403, 'The security token is invalid or expired.', 'CSRF_REJECTED'));
      return;
    }

    delete (body as Record<string, unknown>)['_csrf'];
    response.locals['csrfToken'] = expected;
    next();
  };
}
