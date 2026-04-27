import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createApp } from '../src/app.js';

test('notes require authentication', async (t) => {
  const fixture = await startFixture(t);
  const response = await fixture.agent.request('/notes');

  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/login');
});

test('users can register and create escaped notes', async (t) => {
  const fixture = await startFixture(t);
  const agent = fixture.agent;

  const registerToken = await agent.csrf('/register');
  const registerResponse = await agent.request('/register', {
    body: form({
      _csrf: registerToken,
      password: 'correct horse battery',
      username: 'alice'
    }),
    method: 'POST'
  });

  assert.equal(registerResponse.status, 303);
  assert.equal(registerResponse.headers.get('location'), '/notes');

  const newToken = await agent.csrf('/notes/new');
  const createResponse = await agent.request('/notes', {
    body: form({
      _csrf: newToken,
      body: '<img src=x onerror=alert(1)>',
      title: '<script>alert(1)</script>'
    }),
    method: 'POST'
  });

  assert.equal(createResponse.status, 303);

  const notesResponse = await agent.request('/notes');
  const html = await notesResponse.text();

  assert.equal(notesResponse.status, 200);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(notesResponse.headers.get('content-security-policy') || '', /default-src 'none'/);
});

test('csrf tokens are required for state changes', async (t) => {
  const fixture = await startFixture(t);
  const agent = fixture.agent;

  await register(agent, 'bob');

  const response = await agent.request('/notes', {
    body: form({ body: 'body', title: 'title' }),
    method: 'POST'
  });

  assert.equal(response.status, 403);
});

test('users cannot modify notes they do not own', async (t) => {
  const fixture = await startFixture(t);
  const alice = fixture.agent;
  const bob = fixture.newAgent();

  await register(alice, 'alice');
  const aliceNoteToken = await alice.csrf('/notes/new');
  await alice.request('/notes', {
    body: form({ _csrf: aliceNoteToken, body: 'private', title: 'Alice note' }),
    method: 'POST'
  });

  await register(bob, 'bob');
  const bobNotes = await bob.request('/notes');
  const bobToken = extractCsrf(await bobNotes.text());
  const response = await bob.request('/notes/1', {
    body: form({ _csrf: bobToken, body: 'stolen', title: 'Changed' }),
    method: 'POST'
  });

  assert.equal(response.status, 404);
});

async function register(agent, username) {
  const token = await agent.csrf('/register');
  const response = await agent.request('/register', {
    body: form({
      _csrf: token,
      password: 'correct horse battery',
      username
    }),
    method: 'POST'
  });
  assert.equal(response.status, 303);
}

async function startFixture(t) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-notes-'));
  const { app, db } = createApp({
    cookieName: 'secure_notes_test',
    databaseFile: path.join(tempDir, 'test.sqlite'),
    env: 'test',
    isProduction: false,
    secureCookies: false
  });

  const server = await new Promise((resolve) => {
    const listener = app.listen(0, () => resolve(listener));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    fs.rmSync(tempDir, { force: true, recursive: true });
  });

  return {
    agent: new Agent(baseUrl),
    newAgent: () => new Agent(baseUrl)
  };
}

class Agent {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookies = new Map();
  }

  async csrf(pathname) {
    const response = await this.request(pathname);
    assert.equal(response.status, 200);
    return extractCsrf(await response.text());
  }

  async request(pathname, options = {}) {
    const headers = new Headers(options.headers || {});
    const cookieHeader = [...this.cookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    if (cookieHeader) headers.set('cookie', cookieHeader);

    if (options.body instanceof URLSearchParams) {
      headers.set('content-type', 'application/x-www-form-urlencoded');
    }

    const response = await fetch(`${this.baseUrl}${pathname}`, {
      ...options,
      headers,
      redirect: 'manual'
    });

    const setCookies = typeof response.headers.getSetCookie === 'function'
      ? response.headers.getSetCookie()
      : [response.headers.get('set-cookie')].filter(Boolean);

    for (const setCookie of setCookies) {
      const [pair] = setCookie.split(';');
      const separator = pair.indexOf('=');
      if (separator === -1) continue;
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      if (value) this.cookies.set(name, value);
      else this.cookies.delete(name);
    }

    return response;
  }
}

function form(values) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    params.set(key, value);
  }
  return params;
}

function extractCsrf(html) {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(match, 'expected csrf token field');
  return match[1];
}
