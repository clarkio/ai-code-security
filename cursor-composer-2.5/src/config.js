import 'dotenv/config';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, '..');

function requireEnv(name) {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

const sessionSecret = process.env.SESSION_SECRET?.trim() ?? '';
if (sessionSecret.length < 32) {
  throw new Error(
    'SESSION_SECRET must be at least 32 characters. Generate with: openssl rand -base64 48'
  );
}

const nodeEnv = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const isProduction = nodeEnv === 'production';

const databasePath = resolve(
  rootDir,
  process.env.DATABASE_PATH?.trim() || './data/notes.db'
);
const dataDir = dirname(databasePath);
if (!existsSync(dataDir)) {
  mkdirSync(dataDir, { recursive: true });
}

export const config = {
  rootDir,
  nodeEnv,
  isProduction,
  port: Number.parseInt(process.env.PORT ?? '3000', 10) || 3000,
  host: process.env.HOST?.trim() || '127.0.0.1',
  trustProxy: process.env.TRUST_PROXY === 'true',
  sessionSecret,
  databasePath,
  bcryptRounds: 12,
  sessionMaxAgeMs: 24 * 60 * 60 * 1000,
  noteTitleMaxLength: 200,
  noteBodyMaxLength: 10_000,
  usernameMinLength: 3,
  usernameMaxLength: 32,
  passwordMinLength: 12,
  passwordMaxLength: 128,
};
