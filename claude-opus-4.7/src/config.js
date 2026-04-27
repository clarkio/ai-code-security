'use strict';

const path = require('node:path');
const { z } = require('zod');

require('dotenv').config();

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default('127.0.0.1'),
  TRUST_PROXY: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  // Require a strong secret. 64 hex chars = 32 bytes of entropy minimum.
  SESSION_SECRET: z
    .string()
    .min(64, 'SESSION_SECRET must be at least 64 characters of high-entropy random data'),
  DATABASE_PATH: z.string().min(1).default('./data/app.sqlite'),
});

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  // Print issues without echoing secret values.
  const issues = parsed.error.issues
    .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('\n');
  // eslint-disable-next-line no-console
  console.error(`Invalid environment configuration:\n${issues}`);
  process.exit(1);
}

const env = parsed.data;

const config = Object.freeze({
  env: env.NODE_ENV,
  isProd: env.NODE_ENV === 'production',
  port: env.PORT,
  host: env.HOST,
  trustProxy: env.TRUST_PROXY,
  sessionSecret: env.SESSION_SECRET,
  databasePath: path.resolve(process.cwd(), env.DATABASE_PATH),

  bcryptCost: 12,

  session: {
    name: 'sid',
    cookieMaxAgeMs: 1000 * 60 * 60 * 8, // 8 hours
    rollingRefresh: true,
  },

  limits: {
    bodyJsonBytes: 16 * 1024,
    bodyUrlencodedBytes: 16 * 1024,
    noteTitleMax: 200,
    noteBodyMax: 10_000,
    usernameMin: 3,
    usernameMax: 32,
    passwordMin: 12,
    passwordMax: 128,
  },
});

module.exports = config;
