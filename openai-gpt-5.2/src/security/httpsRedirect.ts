import type { RequestHandler } from 'express';
import { isProd } from '../config';

export function httpsRedirectMiddleware(): RequestHandler {
  return (req, res, next) => {
    if (!isProd) return next();

    const proto = req.get('x-forwarded-proto');
    const isHttps = req.secure || proto === 'https';

    if (isHttps) return next();

    const host = req.get('host');
    if (!host) return res.status(400).send('Bad Request');

    return res.redirect(301, `https://${host}${req.originalUrl}`);
  };
}
