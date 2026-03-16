const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const request = require("supertest");

const { createApp } = require("../src/app");
const { hashPassword } = require("../src/security");

function extractCsrfToken(html) {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  if (!match) {
    throw new Error("CSRF token not found in HTML response.");
  }

  return match[1];
}

function buildApp() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secure-notes-"));

  return createApp({
    env: "test",
    isProduction: false,
    rootDir: process.cwd(),
    dataDir: tempDir,
    databasePath: path.join(tempDir, "notes.json"),
    sessionDir: path.join(tempDir, "sessions"),
    sessionSecret: "test-session-secret",
    adminUsername: "admin",
    adminPasswordHash: hashPassword("correct horse battery staple"),
    trustProxy: false,
    globalRateLimitMax: 1000,
    authRateLimitMax: 1000,
    port: 0,
  });
}

test("unauthenticated users are redirected to login", async () => {
  const app = buildApp();
  const response = await request(app).get("/notes");
  assert.equal(response.status, 302);
  assert.equal(response.headers.location, "/login");
});

test("login, create, update, and delete note flow works", async () => {
  const app = buildApp();
  const agent = request.agent(app);

  const loginPage = await agent.get("/login");
  const loginToken = extractCsrfToken(loginPage.text);

  const loginResponse = await agent.post("/login").type("form").send({
    _csrf: loginToken,
    username: "admin",
    password: "correct horse battery staple",
  });

  assert.equal(loginResponse.status, 302);
  assert.equal(loginResponse.headers.location, "/notes");

  const notesPage = await agent.get("/notes");
  const notesToken = extractCsrfToken(notesPage.text);
  assert.match(notesPage.text, /Create note/);

  const createResponse = await agent.post("/notes").type("form").send({
    _csrf: notesToken,
    title: "First note",
    content: "Hello world",
  });

  assert.equal(createResponse.status, 302);

  const updatedNotesPage = await agent.get("/notes");
  assert.match(updatedNotesPage.text, /First note/);
  const editLinkMatch = updatedNotesPage.text.match(/\/notes\/(\d+)\/edit/);
  assert.ok(editLinkMatch);
  const noteId = editLinkMatch[1];

  const editPage = await agent.get(`/notes/${noteId}/edit`);
  const editToken = extractCsrfToken(editPage.text);

  const updateResponse = await agent
    .post(`/notes/${noteId}`)
    .type("form")
    .send({
      _csrf: editToken,
      title: "Updated note",
      content: "Updated content",
    });

  assert.equal(updateResponse.status, 302);

  const afterUpdate = await agent.get("/notes");
  assert.match(afterUpdate.text, /Updated note/);
  assert.match(afterUpdate.text, /Updated content/);

  const deleteToken = extractCsrfToken(afterUpdate.text);
  const deleteResponse = await agent
    .post(`/notes/${noteId}/delete`)
    .type("form")
    .send({
      _csrf: deleteToken,
    });

  assert.equal(deleteResponse.status, 302);

  const afterDelete = await agent.get("/notes");
  assert.doesNotMatch(afterDelete.text, /Updated note/);
});

test("csrf protection blocks state changes without a token", async () => {
  const app = buildApp();
  const agent = request.agent(app);

  const loginPage = await agent.get("/login");
  const loginToken = extractCsrfToken(loginPage.text);

  await agent.post("/login").type("form").send({
    _csrf: loginToken,
    username: "admin",
    password: "correct horse battery staple",
  });

  const response = await agent.post("/notes").type("form").send({
    title: "Blocked",
    content: "Missing token",
  });

  assert.equal(response.status, 403);
  assert.match(response.text, /Security validation failed/);
});

test("stored note content is escaped on render", async () => {
  const app = buildApp();
  const agent = request.agent(app);

  const loginPage = await agent.get("/login");
  const loginToken = extractCsrfToken(loginPage.text);

  await agent.post("/login").type("form").send({
    _csrf: loginToken,
    username: "admin",
    password: "correct horse battery staple",
  });

  const notesPage = await agent.get("/notes");
  const notesToken = extractCsrfToken(notesPage.text);

  await agent.post("/notes").type("form").send({
    _csrf: notesToken,
    title: "xss",
    content: "<script>alert('xss')</script>",
  });

  const response = await agent.get("/notes");
  assert.doesNotMatch(response.text, /<script>alert\('xss'\)<\/script>/);
  assert.match(response.text, /&lt;script&gt;alert/);
});
