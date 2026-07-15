import proxyaddr from 'proxy-addr';
import { z } from 'zod';

const rawConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  HOST: z.string().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  PUBLIC_ORIGIN: z.string().min(1),
  DATABASE_URL: z.string().min(1),
  DATABASE_SSL: z.enum(['disable', 'require', 'verify-full']).optional(),
  SESSION_SECRETS: z.string().min(1),
  SESSION_TTL_MINUTES: z.coerce.number().int().min(15).max(10_080).default(480),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
  TRUST_PROXY_CIDRS: z.string().default(''),
  MAX_NOTES_PER_USER: z.coerce.number().int().min(1).max(100).default(100),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(10_000),
});

export type Environment = 'development' | 'test' | 'production';
export type DatabaseSslMode = 'disable' | 'require' | 'verify-full';

export interface AppConfig {
  readonly environment: Environment;
  readonly isProduction: boolean;
  readonly host: string;
  readonly port: number;
  readonly publicOrigin: string;
  readonly databaseUrl: string;
  readonly databaseSsl: DatabaseSslMode;
  readonly sessionSecrets: readonly [string, ...string[]];
  readonly sessionTtlMs: number;
  readonly trustProxyHops: number;
  readonly trustedProxyCidrs: readonly string[];
  readonly maxNotesPerUser: number;
  readonly logLevel: string;
  readonly shutdownTimeoutMs: number;
}

function parseOrigin(value: string, production: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('PUBLIC_ORIGIN must be an absolute http(s) origin');
  }

  const isBareOrigin =
    url.origin === value &&
    url.pathname === '/' &&
    url.username === '' &&
    url.password === '' &&
    url.search === '' &&
    url.hash === '';

  if (!isBareOrigin || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('PUBLIC_ORIGIN must contain only an http(s) scheme, hostname, and optional port');
  }
  if (production && url.protocol !== 'https:') {
    throw new Error('PUBLIC_ORIGIN must use HTTPS in production');
  }
  return url.origin;
}

function parseDatabaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('DATABASE_URL must be an absolute PostgreSQL URL');
  }
  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    url.hostname === '' ||
    url.pathname.length <= 1 ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(
      'DATABASE_URL must identify a PostgreSQL host and database without query parameters or fragments',
    );
  }
  return value;
}

function parseSessionSecrets(value: string): readonly [string, ...string[]] {
  const secrets = value.split(',').map((secret) => secret.trim());
  if (secrets.some((secret) => Buffer.byteLength(secret, 'utf8') < 32)) {
    throw new Error('Every SESSION_SECRETS value must be at least 32 bytes');
  }
  const first = secrets[0];
  if (first === undefined) {
    throw new Error('SESSION_SECRETS must contain at least one secret');
  }
  return [first, ...secrets.slice(1)];
}

function parseTrustedProxyCidrs(value: string, hops: number): readonly string[] {
  const cidrs = value
    .split(',')
    .map((cidr) => cidr.trim())
    .filter((cidr) => cidr !== '');

  if (hops === 0 && cidrs.length > 0) {
    throw new Error('TRUST_PROXY_CIDRS must be empty when TRUST_PROXY_HOPS is 0');
  }
  if (hops > 0 && cidrs.length === 0) {
    throw new Error('TRUST_PROXY_CIDRS must list the explicit proxy networks when proxy trust is enabled');
  }
  if (cidrs.some((cidr) => !cidr.includes('/'))) {
    throw new Error('Every TRUST_PROXY_CIDRS entry must use explicit CIDR notation');
  }
  try {
    proxyaddr.compile(cidrs);
  } catch {
    throw new Error('TRUST_PROXY_CIDRS contains an invalid network');
  }
  return Object.freeze([...new Set(cidrs)]);
}

export function parseConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const raw = rawConfigSchema.parse(environment);
  const isProduction = raw.NODE_ENV === 'production';
  const databaseSsl = raw.DATABASE_SSL ?? (isProduction ? 'verify-full' : 'disable');

  if (isProduction && databaseSsl !== 'verify-full') {
    throw new Error('DATABASE_SSL must be verify-full in production');
  }
  if (isProduction && raw.TRUST_PROXY_HOPS === 0) {
    throw new Error('TRUST_PROXY_HOPS must describe at least one TLS-terminating proxy in production');
  }
  if (isProduction && environment['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
    throw new Error('NODE_TLS_REJECT_UNAUTHORIZED=0 is forbidden in production');
  }
  const trustedProxyCidrs = parseTrustedProxyCidrs(raw.TRUST_PROXY_CIDRS, raw.TRUST_PROXY_HOPS);

  return Object.freeze({
    environment: raw.NODE_ENV,
    isProduction,
    host: raw.HOST,
    port: raw.PORT,
    publicOrigin: parseOrigin(raw.PUBLIC_ORIGIN, isProduction),
    databaseUrl: parseDatabaseUrl(raw.DATABASE_URL),
    databaseSsl,
    sessionSecrets: parseSessionSecrets(raw.SESSION_SECRETS),
    sessionTtlMs: raw.SESSION_TTL_MINUTES * 60_000,
    trustProxyHops: raw.TRUST_PROXY_HOPS,
    trustedProxyCidrs,
    maxNotesPerUser: raw.MAX_NOTES_PER_USER,
    logLevel: raw.LOG_LEVEL,
    shutdownTimeoutMs: raw.SHUTDOWN_TIMEOUT_MS,
  });
}
