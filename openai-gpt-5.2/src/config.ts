import dotenv from 'dotenv';
import { z } from 'zod';

if (process.env.NODE_ENV !== 'production') {
  dotenv.config({ quiet: true });
}

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  TRUST_PROXY: z
    .string()
    .optional()
    .transform((v) => v === 'true'),
  COOKIE_SECURE: z
    .string()
    .optional()
    .transform((v) => v === 'true'),
  SESSION_PASSWORD: z.string().min(32),
  CSRF_SECRET: z.string().min(32),
  DATABASE_URL: z.string().min(1),
  LOG_LEVEL: z.string().default('info'),
});

export type AppConfig = z.infer<typeof envSchema>;

export const config: AppConfig = envSchema.parse({
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  TRUST_PROXY: process.env.TRUST_PROXY,
  COOKIE_SECURE: process.env.COOKIE_SECURE,
  SESSION_PASSWORD: process.env.SESSION_PASSWORD,
  CSRF_SECRET: process.env.CSRF_SECRET,
  DATABASE_URL: process.env.DATABASE_URL,
  LOG_LEVEL: process.env.LOG_LEVEL,
});

export const isProd = config.NODE_ENV === 'production';
