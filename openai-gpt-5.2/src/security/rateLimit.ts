import rateLimit from 'express-rate-limit';
import type { RequestHandler } from 'express';

export const globalRateLimit: RequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRateLimit: RequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
