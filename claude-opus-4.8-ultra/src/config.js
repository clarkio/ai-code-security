'use strict';

/**
 * Centralised, validated configuration.
 *
 * Security principle: fail fast and loud. The process refuses to start if a
 * required secret is missing or weak, so we never accidentally boot with an
 * insecure default in production.
 */

require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

function required(name) {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(
      `Missing required environment variable "${name}". ` +
        `Copy .env.example to .env and set it before starting.`
    );
  }
  return value;
}

// A strong session secret is non-negotiable. We require a high-entropy value
// (generate with: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))").
const sessionSecret = required('SESSION_SECRET');
if (sessionSecret.length < 32) {
  throw new Error(
    'SESSION_SECRET must be at least 32 characters of high-entropy randomness.'
  );
}
// Reject obviously-placeholder secrets so a copied .env.example can't ship.
if (/^(changeme|secret|password|example|replace-me)/i.test(sessionSecret)) {
  throw new Error('SESSION_SECRET looks like a placeholder. Generate a real random value.');
}

const config = Object.freeze({
  isProduction,
  port: Number.parseInt(process.env.PORT || '3000', 10),
  // Bind to localhost by default; set HOST=0.0.0.0 explicitly to expose it.
  host: process.env.HOST || '127.0.0.1',
  sessionSecret,
  databasePath: process.env.DATABASE_PATH || './data/notes.db',
  // Number of reverse proxies in front of the app (for correct secure-cookie /
  // client-IP handling). 0 = no proxy (direct). Set to 1 behind nginx/Heroku.
  trustProxy: Number.parseInt(process.env.TRUST_PROXY || '0', 10),
  // bcrypt work factor. 12 is a sane 2024-era default.
  bcryptRounds: 12,
  // Session lifetime: 7 days.
  sessionMaxAgeMs: 7 * 24 * 60 * 60 * 1000,
});

module.exports = config;
