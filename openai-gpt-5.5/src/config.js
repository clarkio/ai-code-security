import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function readBoolean(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (/^(1|true|yes|on)$/i.test(value)) return true;
  if (/^(0|false|no|off)$/i.test(value)) return false;
  throw new Error(`${name} must be a boolean value`);
}

function readInteger(name, fallback, { min, max }) {
  const raw = process.env[name];
  const value = raw === undefined || raw === '' ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function readOrigin(value) {
  if (!value) return null;
  const url = new URL(value);
  return url.origin;
}

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';
const port = readInteger('PORT', 3000, { min: 1, max: 65535 });
const secureCookies = readBoolean('SESSION_COOKIE_SECURE', isProduction);
const appOrigin = readOrigin(process.env.APP_ORIGIN || (isProduction ? '' : null));

if (isProduction && !appOrigin) {
  throw new Error('APP_ORIGIN is required in production, for example https://notes.example.com');
}

if (isProduction && !secureCookies) {
  throw new Error('SESSION_COOKIE_SECURE must stay enabled in production');
}

export const config = Object.freeze({
  appOrigin,
  cookieName: secureCookies ? '__Host-secure_notes' : 'secure_notes',
  databaseFile: process.env.DATABASE_FILE || path.join(projectRoot, 'data', 'notes.sqlite'),
  env,
  isProduction,
  port,
  projectRoot,
  secureCookies,
  sessionDays: readInteger('SESSION_DAYS', 7, { min: 1, max: 30 }),
  trustProxy: readBoolean('TRUST_PROXY', false)
});
