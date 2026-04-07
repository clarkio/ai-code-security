import dotenv from 'dotenv';
dotenv.config();

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.join(__dirname, '..');

function requireEnv(name, minLen) {
  const v = process.env[name];
  if (!v || (minLen && v.length < minLen)) {
    throw new Error(
      `${name} must be set${minLen ? ` and at least ${minLen} characters` : ''} in production`
    );
  }
  return v;
}

const isProd = process.env.NODE_ENV === 'production';

const sessionSecret = isProd
  ? requireEnv('SESSION_SECRET', 32)
  : (process.env.SESSION_SECRET || 'local-dev-only-use-env-in-real-deploy-32');

export const config = {
  isProd,
  port: Number.parseInt(process.env.PORT || '3000', 10),
  trustProxy: process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true',
  sessionSecret,
  databasePath: path.resolve(rootDir, process.env.DATABASE_PATH || './data/notes.db'),
  sessionFilesDir: path.resolve(rootDir, process.env.SESSION_FILES_DIR || './data/sessions'),
  sessionCookieName: 'sid',
  rootDir,
};

if (config.sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters');
}
