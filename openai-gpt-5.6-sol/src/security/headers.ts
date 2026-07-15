import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from '../config.js';
import { HttpError } from '../errors.js';

export function productionRequestGuard(config: AppConfig) {
  const expectedHost = new URL(config.publicOrigin).host;

  return (request: Request, _response: Response, next: NextFunction): void => {
    if (!config.isProduction) {
      next();
      return;
    }

    // Private orchestrator probes reach the HTTP listener directly and carry
    // no session or user data. Network policy should keep these endpoints from
    // becoming an alternate public path.
    if (
      request.method === 'GET' &&
      (request.path === '/health/live' || request.path === '/health/ready')
    ) {
      next();
      return;
    }

    if (!request.secure) {
      next(new HttpError(400, 'HTTPS is required.', 'HTTPS_REQUIRED'));
      return;
    }

    if (request.get('host') !== expectedHost) {
      next(new HttpError(400, 'The request host is invalid.', 'INVALID_HOST'));
      return;
    }

    next();
  };
}
