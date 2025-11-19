process.env.NODE_ENV = 'test';
process.env.DB_FILE = ':memory:';
process.env.ALLOW_REGISTRATION = '1';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const app = require('../src/server');
const { migrate, run } = require('../src/db');

const withCsrf = async (agent) => {
  const res = await agent.get('/csrf-token');
  assert.equal(res.status, 200);
  assert.ok(res.body.csrfToken);
  return res.body.csrfToken;
};

test.before(async () => {
  await migrate();
});

test.beforeEach(async () => {
  await run('DELETE FROM notes');
  await run('DELETE FROM users');
});

test('register, login, and CRUD notes', async () => {
  const agent = request.agent(app);

  const csrfRegister = await withCsrf(agent);
  const registerRes = await agent
    .post('/auth/register')
    .set('x-csrf-token', csrfRegister)
    .send({ username: 'alice', password: 'AAaa11!!moretext' });
  assert.equal(registerRes.status, 201);
  assert.ok(registerRes.body.id);

  const csrfNote = await withCsrf(agent);
  const createRes = await agent
    .post('/notes')
    .set('x-csrf-token', csrfNote)
    .send({ title: 'Hello', content: 'Secure world' });
  assert.equal(createRes.status, 201);
  assert.ok(createRes.body.id);

  const listRes = await agent.get('/notes');
  assert.equal(listRes.status, 200);
  assert.equal(listRes.body.notes.length, 1);

  const csrfUpdate = await withCsrf(agent);
  const updateRes = await agent
    .put(`/notes/${createRes.body.id}`)
    .set('x-csrf-token', csrfUpdate)
    .send({ title: 'Updated', content: 'Changed content' });
  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.body.title, 'Updated');

  const csrfDelete = await withCsrf(agent);
  const deleteRes = await agent
    .delete(`/notes/${createRes.body.id}`)
    .set('x-csrf-token', csrfDelete);
  assert.equal(deleteRes.status, 200);
  assert.equal(deleteRes.body.success, true);
});

test('rejects unauthorized access', async () => {
  const res = await request(app).get('/notes');
  assert.equal(res.status, 401);
});

