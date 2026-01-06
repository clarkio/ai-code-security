import helmet from 'helmet';
import type { RequestHandler } from 'express';
import { isProd } from '../config';

export function helmetMiddleware(): RequestHandler {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'base-uri': ["'none'"],
        'object-src': ["'none'"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'"],
        ...(isProd ? { 'upgrade-insecure-requests': [] } : {}),
      },
    },
    crossOriginEmbedderPolicy: false,
  });
}
