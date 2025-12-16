const request = require('supertest');
const app = require('../src/index');

describe('notes CRUD', () => {
  test('create, update, delete a note', async () => {
    const agent = request.agent(app);
    const username = `u${Date.now()}`;
    const password = 'A-very-strong-passw0rd!';

    // Register
    const reg = await agent.post('/api/auth/register').send({ username, password });
    expect(reg.status).toBe(201);

    // Get CSRF token
    const tokenRes = await agent.get('/api/csrf-token');
    expect(tokenRes.status).toBe(200);
    const csrfToken = tokenRes.body.csrfToken;
    expect(csrfToken).toBeDefined();

    // Create note
    const noteRes = await agent.post('/api/notes').set('X-CSRF-Token', csrfToken).send({ title: 't', body: 'b' });
    expect(noteRes.status).toBe(201);
    const noteId = noteRes.body.id;

    // Update
    const tokenRes2 = await agent.get('/api/csrf-token');
    const csrfToken2 = tokenRes2.body.csrfToken;
    const upd = await agent.put(`/api/notes/${noteId}`).set('X-CSRF-Token', csrfToken2).send({ title: 't2', body: 'b2' });
    expect(upd.status).toBe(200);

    // Delete
    const tokenRes3 = await agent.get('/api/csrf-token');
    const csrfToken3 = tokenRes3.body.csrfToken;
    const del = await agent.delete(`/api/notes/${noteId}`).set('X-CSRF-Token', csrfToken3);
    expect(del.status).toBe(200);
  });
});