import type { NextFunction, Request, Response } from 'express';

export function requireAuthentication(request: Request, response: Response, next: NextFunction): void {
  const userId = request.session.userId;
  if (userId === undefined) {
    response.redirect(303, '/login');
    return;
  }
  request.authenticatedUserId = userId;
  next();
}

export function requireGuest(request: Request, response: Response, next: NextFunction): void {
  if (request.session.userId !== undefined) {
    response.redirect(303, '/notes');
    return;
  }
  next();
}

export function exposeFlash(request: Request, response: Response, next: NextFunction): void {
  response.locals['flash'] = request.session.flash;
  if (request.session.flash !== undefined) delete request.session.flash;
  next();
}
