import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseConfig } from '../src/config.js';

const validEnvironment = {
  NODE_ENV: 'production',
  HOST: '0.0.0.0',
  PORT: '3000',
  PUBLIC_ORIGIN: 'https://notes.example.test',
  DATABASE_URL: 'postgresql://notes:password@database.example.test/notes',
  DATABASE_SSL: 'verify-full',
  SESSION_SECRETS: 'a-random-production-secret-with-more-than-32-bytes',
  TRUST_PROXY_HOPS: '1',
  TRUST_PROXY_CIDRS: '127.0.0.1/32',
} satisfies NodeJS.ProcessEnv;

test('production configuration requires HTTPS, verified database TLS, and a trusted proxy', () => {
  assert.doesNotThrow(() => parseConfig(validEnvironment));
  assert.throws(
    () => parseConfig({ ...validEnvironment, PUBLIC_ORIGIN: 'http://notes.example.test' }),
    /must use HTTPS/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, DATABASE_SSL: 'require' }),
    /must be verify-full/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, DATABASE_SSL: 'disable' }),
    /must be verify-full/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, TRUST_PROXY_HOPS: '0' }),
    /TLS-terminating proxy/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, TRUST_PROXY_CIDRS: '' }),
    /explicit proxy networks/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, TRUST_PROXY_CIDRS: 'not-a-network' }),
    /explicit CIDR notation/iu,
  );
  assert.throws(() => parseConfig({ ...validEnvironment, MAX_NOTES_PER_USER: '101' }));
});

test('configuration rejects weak secrets and malformed origins/database URLs', () => {
  assert.throws(
    () => parseConfig({ ...validEnvironment, SESSION_SECRETS: 'too-short' }),
    /at least 32 bytes/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, PUBLIC_ORIGIN: 'https://notes.example.test/path' }),
    /scheme, hostname, and optional port/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, DATABASE_URL: 'https://database.example.test/notes' }),
    /PostgreSQL host and database/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, DATABASE_URL: 'postgresql://database.example.test/' }),
    /PostgreSQL host and database/iu,
  );
  assert.throws(
    () =>
      parseConfig({
        ...validEnvironment,
        DATABASE_URL: 'postgresql://database.example.test/notes?sslmode=no-verify',
      }),
    /without query parameters/iu,
  );
  assert.throws(
    () => parseConfig({ ...validEnvironment, NODE_TLS_REJECT_UNAUTHORIZED: '0' }),
    /forbidden in production/iu,
  );
});

test('session secret rotation keeps the first secret active and retains older verifiers', () => {
  const first = 'first-random-session-secret-with-at-least-32-bytes';
  const old = 'older-random-session-secret-with-at-least-32-bytes';
  const config = parseConfig({ ...validEnvironment, SESSION_SECRETS: `${first},${old}` });
  assert.deepEqual(config.sessionSecrets, [first, old]);
});
