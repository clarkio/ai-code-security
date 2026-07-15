import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import request from 'supertest';
import { hashPassword } from '../src/security/password.js';
import {
  cookiePair,
  createHarness,
  createTestConfig,
  csrfFrom,
  csrfFromPage,
  login,
  setCookies,
} from './support/harness.js';

const PASSWORD = 'correct horse battery staple';
const PASSWORD_HASH = await hashPassword(PASSWORD);

async function seedAndLogin(
  harness: ReturnType<typeof createHarness>,
  email: string,
  id = randomUUID(),
) {
  const user = harness.users.seed(email, PASSWORD_HASH, id);
  const agent = request.agent(harness.app);
  const response = await login(agent, email, PASSWORD);
  assert.equal(response.status, 303);
  assert.equal(response.headers['location'], '/notes');
  return { agent, user };
}

test('registration has the same generic outcome for new and duplicate accounts and does not sign in', async () => {
  const harness = createHarness();

  const register = async () => {
    const agent = request.agent(harness.app);
    const token = await csrfFromPage(agent, '/register');
    const response = await agent.post('/register').type('form').send({
      _csrf: token,
      email: 'alice@example.test',
      password: PASSWORD,
      passwordConfirm: PASSWORD,
    });
    return { agent, response };
  };

  const first = await register();
  const duplicate = await register();

  for (const attempt of [first, duplicate]) {
    assert.equal(attempt.response.status, 303);
    assert.equal(attempt.response.headers['location'], '/login');
    const protectedResponse = await attempt.agent.get('/notes');
    assert.equal(protectedResponse.status, 303);
    assert.equal(protectedResponse.headers['location'], '/login');
  }

  const loginResponse = await login(first.agent, 'alice@example.test', PASSWORD);
  assert.equal(loginResponse.status, 303);
  assert.equal(loginResponse.headers['location'], '/notes');
});

test('unknown accounts and incorrect passwords receive the same login failure', async () => {
  const harness = createHarness();
  harness.users.seed('alice@example.test', PASSWORD_HASH);

  const incorrectPasswordAgent = request.agent(harness.app);
  const incorrectPasswordToken = await csrfFromPage(incorrectPasswordAgent, '/login');
  const incorrectPassword = await incorrectPasswordAgent.post('/login').type('form').send({
    _csrf: incorrectPasswordToken,
    email: 'alice@example.test',
    password: 'this password is incorrect',
  });

  const unknownAccountAgent = request.agent(harness.app);
  const unknownAccountToken = await csrfFromPage(unknownAccountAgent, '/login');
  const unknownAccount = await unknownAccountAgent.post('/login').type('form').send({
    _csrf: unknownAccountToken,
    email: 'unknown@example.test',
    password: 'this password is incorrect',
  });

  for (const response of [incorrectPassword, unknownAccount]) {
    assert.equal(response.status, 401);
    assert.match(response.text, /Email or password is incorrect\./u);
    assert.doesNotMatch(response.text, /account (?:exists|does not exist)|unknown user/iu);
  }
});

test('authentication rate limiting counts registration attempts, including valid-looking ones', async () => {
  const harness = createHarness();
  const agent = request.agent(harness.app);
  const token = await csrfFromPage(agent, '/register');

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const response = await agent.post('/register').type('form').send({
      _csrf: token,
      email: `invalid-${attempt}@example.test`,
      password: 'short',
      passwordConfirm: 'short',
    });
    assert.equal(response.status, 400);
  }

  const limited = await agent.post('/register').type('form').send({
    _csrf: token,
    email: 'another@example.test',
    password: PASSWORD,
    passwordConfirm: PASSWORD,
  });
  assert.equal(limited.status, 429);
  assert.match(limited.text, /too many authentication attempts/iu);
  assert.equal(await harness.users.findByEmail('another@example.test'), undefined);
});

test('authentication forms reject submissions without a session CSRF token', async () => {
  const harness = createHarness();
  harness.users.seed('alice@example.test', PASSWORD_HASH);

  const loginAgent = request.agent(harness.app);
  const loginResponse = await loginAgent.post('/login').type('form').send({
    email: 'alice@example.test',
    password: PASSWORD,
  });
  assert.equal(loginResponse.status, 403);
  assert.equal((await loginAgent.get('/notes')).status, 303);

  const registerAgent = request.agent(harness.app);
  const registerResponse = await registerAgent.post('/register').type('form').send({
    email: 'mallory@example.test',
    password: PASSWORD,
    passwordConfirm: PASSWORD,
  });
  assert.equal(registerResponse.status, 403);
  assert.match(registerResponse.text, /security token is invalid or expired/iu);
});

test('development accepts a valid CSRF form from the same request origin', async () => {
  const harness = createHarness({
    config: createTestConfig({ publicOrigin: 'http://localhost:3000' }),
  });
  const agent = request.agent(harness.app);
  const registerPage = await agent.get('/register').set('Host', '127.0.0.1:3000');
  assert.equal(registerPage.status, 200);

  const response = await agent
    .post('/register')
    .set('Host', '127.0.0.1:3000')
    .set('Origin', 'http://127.0.0.1:3000')
    .type('form')
    .send({
      _csrf: csrfFrom(registerPage.text),
      email: 'loopback@example.test',
      password: PASSWORD,
      passwordConfirm: PASSWORD,
    });

  assert.equal(response.status, 303);
  assert.equal(response.headers['location'], '/login');
  assert.ok(await harness.users.findByEmail('loopback@example.test'));
});

test('successful login rotates the session and logout invalidates the authenticated cookie', async () => {
  const harness = createHarness();
  harness.users.seed('alice@example.test', PASSWORD_HASH);
  const agent = request.agent(harness.app);

  const loginPage = await agent.get('/login');
  assert.equal(loginPage.status, 200);
  const anonymousCookie = cookiePair(loginPage, 'notes.sid');
  const anonymousCsrfToken = csrfFrom(loginPage.text);
  const loginResponse = await agent.post('/login').type('form').send({
    _csrf: anonymousCsrfToken,
    email: 'alice@example.test',
    password: PASSWORD,
  });
  assert.equal(loginResponse.status, 303);
  const authenticatedCookie = cookiePair(loginResponse, 'notes.sid');
  assert.notEqual(authenticatedCookie, anonymousCookie);

  const fixedSessionAttempt = await request(harness.app)
    .get('/notes')
    .set('Cookie', anonymousCookie);
  assert.equal(fixedSessionAttempt.status, 303);
  assert.equal(fixedSessionAttempt.headers['location'], '/login');

  const staleCsrfAttempt = await agent.post('/notes').type('form').send({
    _csrf: anonymousCsrfToken,
    title: 'Stale token',
    content: 'A token from before login must not work after rotation.',
  });
  assert.equal(staleCsrfAttempt.status, 403);

  const notesPage = await agent.get('/notes');
  assert.equal(notesPage.status, 200);
  const logoutWithoutCsrf = await agent.post('/logout').type('form').send({});
  assert.equal(logoutWithoutCsrf.status, 403);
  assert.equal((await agent.get('/notes')).status, 200);
  const logoutResponse = await agent.post('/logout').type('form').send({
    _csrf: csrfFrom(notesPage.text),
  });
  assert.equal(logoutResponse.status, 303);
  assert.equal(logoutResponse.headers['location'], '/login');
  const clearedCookie = setCookies(logoutResponse).find((value) => value.startsWith('notes.sid='));
  assert.ok(clearedCookie);
  assert.match(clearedCookie, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/iu);

  const replayedSession = await request(harness.app)
    .get('/notes')
    .set('Cookie', authenticatedCookie);
  assert.equal(replayedSession.status, 303);
  assert.equal(replayedSession.headers['location'], '/login');
  const loggedOutAgent = await agent.get('/notes');
  assert.equal(loggedOutAgent.status, 303);
});

test('CSRF protection binds form tokens to the session and rejects cross-site submissions', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const bob = await seedAndLogin(harness, 'bob@example.test');

  const aliceToken = await csrfFromPage(alice.agent, '/notes');
  const bobToken = await csrfFromPage(bob.agent, '/notes');
  assert.match(aliceToken, /^[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(aliceToken, bobToken);

  const missingToken = await alice.agent.post('/notes').type('form').send({
    title: 'Must not be created',
    content: 'No CSRF token was submitted.',
  });
  assert.equal(missingToken.status, 403);
  assert.match(missingToken.text, /security token is invalid or expired/iu);

  const tokenFromAnotherSession = await bob.agent.post('/notes').type('form').send({
    _csrf: aliceToken,
    title: 'Must not be created',
    content: 'The token belongs to Alice.',
  });
  assert.equal(tokenFromAnotherSession.status, 403);

  const foreignOrigin = await alice.agent
    .post('/notes')
    .set('Origin', 'https://attacker.example')
    .type('form')
    .send({ _csrf: aliceToken, title: 'Must not be created', content: 'Foreign origin.' });
  assert.equal(foreignOrigin.status, 403);

  const crossSiteFetch = await alice.agent
    .post('/notes')
    .set('Sec-Fetch-Site', 'cross-site')
    .type('form')
    .send({ _csrf: aliceToken, title: 'Must not be created', content: 'Cross-site fetch.' });
  assert.equal(crossSiteFetch.status, 403);

  const validRequest = await alice.agent.post('/notes').type('form').send({
    _csrf: aliceToken,
    title: 'Created safely',
    content: 'This request has the current session token.',
  });
  assert.equal(validRequest.status, 303);
  assert.equal(validRequest.headers['location'], '/notes');

  const aliceNotes = await alice.agent.get('/notes');
  assert.match(aliceNotes.text, /Created safely/u);
  assert.doesNotMatch(aliceNotes.text, /Must not be created/u);
});

test('note routes never reveal, update, or delete another user\'s note', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const bob = await seedAndLogin(harness, 'bob@example.test');
  harness.notes.seed(alice.user.id, { title: 'Alice private note', content: 'Alice only.' });
  const bobNote = harness.notes.seed(bob.user.id, {
    title: 'Bob highly confidential note',
    content: 'Bob secret remains unchanged.',
  });

  const aliceList = await alice.agent.get('/notes');
  assert.equal(aliceList.status, 200);
  assert.match(aliceList.text, /Alice private note/u);
  assert.doesNotMatch(aliceList.text, /Bob highly confidential note|Bob secret remains unchanged/u);
  assert.doesNotMatch(aliceList.text, new RegExp(bobNote.id, 'u'));

  const foreignEdit = await alice.agent.get(`/notes/${bobNote.id}/edit`);
  const nonexistentEdit = await alice.agent.get(`/notes/${randomUUID()}/edit`);
  for (const response of [foreignEdit, nonexistentEdit]) {
    assert.equal(response.status, 404);
    assert.match(response.text, /requested page was not found/iu);
    assert.doesNotMatch(response.text, /Bob highly confidential note|Bob secret remains unchanged/u);
  }

  const aliceToken = csrfFrom(aliceList.text);
  const foreignUpdate = await alice.agent.post(`/notes/${bobNote.id}/update`).type('form').send({
    _csrf: aliceToken,
    title: 'Stolen by Alice',
    content: 'This must never replace Bob\'s content.',
    version: 1,
  });
  assert.equal(foreignUpdate.status, 404);

  const foreignDelete = await alice.agent.post(`/notes/${bobNote.id}/delete`).type('form').send({
    _csrf: aliceToken,
  });
  assert.equal(foreignDelete.status, 404);

  const bobEdit = await bob.agent.get(`/notes/${bobNote.id}/edit`);
  assert.equal(bobEdit.status, 200);
  assert.match(bobEdit.text, /Bob highly confidential note/u);
  assert.match(bobEdit.text, /Bob secret remains unchanged/u);
  assert.doesNotMatch(bobEdit.text, /Stolen by Alice|replace Bob/u);
});

test('an owner can update and delete a note while stale updates fail safely', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const note = harness.notes.seed(alice.user.id, { title: 'Original', content: 'Version one.' });

  const editPage = await alice.agent.get(`/notes/${note.id}/edit`);
  assert.equal(editPage.status, 200);
  const token = csrfFrom(editPage.text);
  const update = await alice.agent.post(`/notes/${note.id}/update`).type('form').send({
    _csrf: token,
    title: 'Current title',
    content: 'Version two.',
    version: 1,
  });
  assert.equal(update.status, 303);

  const staleUpdate = await alice.agent.post(`/notes/${note.id}/update`).type('form').send({
    _csrf: token,
    title: 'Stale title',
    content: 'Must not overwrite.',
    version: 1,
  });
  assert.equal(staleUpdate.status, 409);
  assert.match(staleUpdate.text, /changed in another request/iu);
  assert.match(staleUpdate.text, /Current title|Version two/u);
  assert.doesNotMatch(staleUpdate.text, /Stale title|Must not overwrite/u);

  const notesPage = await alice.agent.get('/notes');
  assert.match(notesPage.text, /Current title/u);
  const remove = await alice.agent.post(`/notes/${note.id}/delete`).type('form').send({
    _csrf: csrfFrom(notesPage.text),
  });
  assert.equal(remove.status, 303);
  const afterDelete = await alice.agent.get('/notes');
  assert.match(afterDelete.text, /0 notes/u);
  assert.doesNotMatch(afterDelete.text, /Current title/u);
});

test('stored note text is escaped in list and edit views', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const token = await csrfFromPage(alice.agent, '/notes');
  const maliciousTitle = '\"><script>globalThis.__xss=1</script>';
  const maliciousContent =
    '<img src=x onerror="globalThis.__xss=2"><svg onload="globalThis.__xss=3"></svg><%- process.exit() %>';

  const createResponse = await alice.agent.post('/notes').type('form').send({
    _csrf: token,
    title: maliciousTitle,
    content: maliciousContent,
  });
  assert.equal(createResponse.status, 303);

  const listResponse = await alice.agent.get('/notes');
  assert.equal(listResponse.status, 200);
  assert.doesNotMatch(listResponse.text, /<script\b|<img\b|<svg\b/iu);
  assert.match(listResponse.text, /&lt;script&gt;globalThis\.__xss=1&lt;\/script&gt;/u);
  assert.match(listResponse.text, /&lt;img src=x onerror=/u);
  assert.match(listResponse.text, /&lt;svg onload=/u);
  assert.match(listResponse.text, /&lt;%- process\.exit\(\) %&gt;/u);

  const editPath = /href="(\/notes\/[0-9a-f-]+\/edit)"/iu.exec(listResponse.text)?.[1];
  assert.ok(editPath, 'created note did not expose its edit link');
  const editResponse = await alice.agent.get(editPath);
  assert.equal(editResponse.status, 200);
  assert.doesNotMatch(editResponse.text, /<script\b|<img\b|<svg\b/iu);
  assert.match(editResponse.text, /&lt;script&gt;globalThis\.__xss=1&lt;\/script&gt;/u);
  assert.match(editResponse.text, /&lt;img src=x onerror=/u);
});

test('note validation rejects malformed, over-limit, duplicate, and mass-assignment fields', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const token = await csrfFromPage(alice.agent, '/notes');
  const invalidPayloads: readonly Record<string, string>[] = [
    { title: '   ', content: 'Valid content.' },
    { title: 'line\nbreak', content: 'Valid content.' },
    { title: 't'.repeat(201), content: 'Valid content.' },
    { title: 'Valid title', content: '   ' },
    { title: 'Valid title', content: 'c'.repeat(10_001) },
    { title: 'Valid title', content: '😀'.repeat(2_600) },
    { title: 'Valid title', content: 'Valid content.', userId: randomUUID() },
    { title: 'Valid title', content: 'Valid\0content.' },
  ];

  for (const payload of invalidPayloads) {
    const response = await alice.agent.post('/notes').type('form').send({ _csrf: token, ...payload });
    assert.equal(response.status, 400);
    assert.match(response.text, /title .* and note .* are required/iu);
  }

  const duplicateFields = await alice.agent
    .post('/notes')
    .type('form')
    .send(`_csrf=${encodeURIComponent(token)}&title=one&title=two&content=Valid`);
  assert.equal(duplicateFields.status, 400);

  const afterInvalidRequests = await alice.agent.get('/notes');
  assert.match(afterInvalidRequests.text, /0 notes/u);

  const boundaryResponse = await alice.agent.post('/notes').type('form').send({
    _csrf: token,
    title: 't'.repeat(200),
    content: 'c'.repeat(10_000),
  });
  assert.equal(boundaryResponse.status, 303);

  const invalidId = await alice.agent.get('/notes/not-a-uuid/edit');
  assert.equal(invalidId.status, 404);
  assert.match(invalidId.text, /requested page was not found/iu);
});

test('mutation endpoints accept only bounded URL-encoded forms', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const token = await csrfFromPage(alice.agent, '/notes');

  const jsonResponse = await alice.agent.post('/notes').send({
    _csrf: token,
    title: 'JSON note',
    content: 'JSON is not an accepted form submission.',
  });
  assert.equal(jsonResponse.status, 415);
  assert.match(jsonResponse.text, /accepts HTML form submissions only/iu);

  const textResponse = await alice.agent
    .post('/notes')
    .type('text')
    .send(`_csrf=${token}&title=Text&content=Plain text`);
  assert.equal(textResponse.status, 415);

  const oversizedResponse = await alice.agent.post('/notes').type('form').send({
    _csrf: token,
    title: 'Oversized request',
    content: 'x'.repeat(37_000),
  });
  assert.equal(oversizedResponse.status, 413);
  assert.match(oversizedResponse.text, /submitted form is too large/iu);

  const notesPage = await alice.agent.get('/notes');
  assert.match(notesPage.text, /0 notes/u);
  assert.doesNotMatch(notesPage.text, /JSON note|Oversized request/u);
});

test('production responses enforce HTTPS, host validation, security headers, and a __Host cookie', async () => {
  const config = createTestConfig({
    environment: 'production',
    isProduction: true,
    publicOrigin: 'https://notes.example.test',
    databaseSsl: 'verify-full',
    trustProxyHops: 1,
    trustedProxyCidrs: ['127.0.0.1/32'],
  });
  const harness = createHarness({ config });

  const response = await request(harness.app)
    .get('/login')
    .set('Host', 'notes.example.test')
    .set('X-Forwarded-Proto', 'https');
  assert.equal(response.status, 200);
  assert.equal(response.headers['x-powered-by'], undefined);
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.match(response.headers['strict-transport-security'] ?? '', /max-age=31536000/iu);
  assert.match(response.headers['strict-transport-security'] ?? '', /includeSubDomains/iu);
  assert.match(response.headers['content-security-policy'] ?? '', /default-src 'self'/u);
  assert.match(response.headers['content-security-policy'] ?? '', /script-src 'none'/u);
  assert.match(response.headers['content-security-policy'] ?? '', /frame-ancestors 'none'/u);
  assert.match(response.headers['permissions-policy'] ?? '', /camera=\(\).*microphone=\(\)/u);
  assert.equal(response.headers['cache-control'], 'no-store');

  const sessionCookie = setCookies(response).find((value) =>
    value.startsWith('__Host-notes.sid='),
  );
  assert.ok(sessionCookie, 'production response did not set the __Host session cookie');
  assert.match(sessionCookie, /; Path=\//u);
  assert.match(sessionCookie, /; HttpOnly/iu);
  assert.match(sessionCookie, /; Secure/iu);
  assert.match(sessionCookie, /; SameSite=Strict/iu);
  assert.match(sessionCookie, /; Priority=High/iu);
  assert.doesNotMatch(sessionCookie, /; Domain=/iu);

  const insecure = await request(harness.app).get('/login').set('Host', 'notes.example.test');
  assert.equal(insecure.status, 400);
  assert.match(insecure.text, /HTTPS is required/iu);

  const privateLivenessProbe = await request(harness.app).get('/health/live');
  assert.equal(privateLivenessProbe.status, 200);
  assert.equal(privateLivenessProbe.text, 'ok');

  const wrongHost = await request(harness.app)
    .get('/login')
    .set('Host', 'attacker.example')
    .set('X-Forwarded-Proto', 'https');
  assert.equal(wrongHost.status, 400);
  assert.match(wrongHost.text, /request host is invalid/iu);

  const untrustedProxyHarness = createHarness({
    config: createTestConfig({
      environment: 'production',
      isProduction: true,
      publicOrigin: 'https://notes.example.test',
      databaseSsl: 'verify-full',
      trustProxyHops: 1,
      trustedProxyCidrs: ['10.0.0.0/8'],
    }),
  });
  const spoofedProto = await request(untrustedProxyHarness.app)
    .get('/login')
    .set('Host', 'notes.example.test')
    .set('X-Forwarded-Proto', 'https');
  assert.equal(spoofedProto.status, 400);
  assert.match(spoofedProto.text, /HTTPS is required/iu);
});

test('unexpected repository failures return a sanitized error page and do not terminate the app', async () => {
  const harness = createHarness();
  const alice = await seedAndLogin(harness, 'alice@example.test');
  const secretMarker = 'super-secret-marker-51b3b88d';
  harness.notes.failListWith(
    new Error(
      `password=${secretMarker}; SELECT password_hash FROM users; postgres://admin:${secretMarker}@db/private`,
    ),
  );

  const response = await alice.agent.get('/notes');
  assert.equal(response.status, 500);
  assert.match(response.text, /An unexpected error occurred\./u);
  assert.doesNotMatch(response.text, new RegExp(secretMarker, 'u'));
  assert.doesNotMatch(response.text, /SELECT password_hash|postgres:\/\/|FakeNoteRepository|Error:/iu);
  assert.equal(response.headers['cache-control'], 'no-store');
  const requestId = response.headers['x-request-id'];
  assert.match(requestId ?? '', /^[0-9a-f-]{36}$/u);
  assert.match(response.text, new RegExp(requestId ?? 'missing-request-id', 'u'));

  const liveness = await request(harness.app).get('/health/live');
  assert.equal(liveness.status, 200);
  assert.equal(liveness.text, 'ok');
});
