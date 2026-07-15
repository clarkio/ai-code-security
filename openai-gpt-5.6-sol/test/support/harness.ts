import assert from 'node:assert/strict';
import session from 'express-session';
import type pg from 'pg';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import type { AppConfig } from '../../src/config.js';
import { FakeNoteRepository, FakeUserRepository } from './fakes.js';

const BASE_CONFIG: AppConfig = Object.freeze({
  environment: 'test',
  isProduction: false,
  host: '127.0.0.1',
  port: 3000,
  publicOrigin: 'http://notes.test',
  databaseUrl: 'postgres://unused/secure_notes_test',
  databaseSsl: 'disable',
  sessionSecrets: ['test-only-session-secret-that-is-longer-than-thirty-two-bytes'] as const,
  sessionTtlMs: 60 * 60_000,
  trustProxyHops: 0,
  trustedProxyCidrs: [],
  maxNotesPerUser: 100,
  logLevel: 'silent',
  shutdownTimeoutMs: 5_000,
});

export type TestAgent = ReturnType<typeof request.agent>;

export interface TestHarness {
  readonly app: ReturnType<typeof createApp>;
  readonly config: AppConfig;
  readonly users: FakeUserRepository;
  readonly notes: FakeNoteRepository;
  readonly sessionStore: session.MemoryStore;
}

export function createTestConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return Object.freeze({ ...BASE_CONFIG, ...overrides });
}

export function createHarness(options: { readonly config?: AppConfig } = {}): TestHarness {
  const config = options.config ?? createTestConfig();
  const users = new FakeUserRepository();
  const notes = new FakeNoteRepository();
  const sessionStore = new session.MemoryStore();
  const pool = {
    query: async () => ({ rows: [{ connected: true }], rowCount: 1 }),
  } as unknown as pg.Pool;

  return {
    app: createApp({ config, pool, sessionStore, users, notes }),
    config,
    users,
    notes,
    sessionStore,
  };
}

export function csrfFrom(html: string): string {
  const match = /name="_csrf" value="([A-Za-z0-9_-]{43})"/u.exec(html);
  assert.ok(match?.[1], 'response did not contain a valid CSRF token');
  return match[1];
}

export async function csrfFromPage(agent: TestAgent, path: string): Promise<string> {
  const response = await agent.get(path);
  assert.equal(response.status, 200);
  return csrfFrom(response.text);
}

export async function login(
  agent: TestAgent,
  email: string,
  password: string,
): Promise<request.Response> {
  const token = await csrfFromPage(agent, '/login');
  return agent.post('/login').type('form').send({ _csrf: token, email, password });
}

export function setCookies(response: request.Response): readonly string[] {
  const value = response.headers['set-cookie'] as string[] | string | undefined;
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

export function cookiePair(response: request.Response, name: string): string {
  const cookie = setCookies(response).find((candidate) => candidate.startsWith(`${name}=`));
  assert.ok(cookie, `response did not set ${name}`);
  const pair = cookie.split(';', 1)[0];
  assert.ok(pair);
  return pair;
}
