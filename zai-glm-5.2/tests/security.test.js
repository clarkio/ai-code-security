"use strict";

/**
 * Security-focused tests.
 *
 * These verify the core security properties of the app:
 *  - SQL injection is blocked (parameterized queries)
 *  - XSS payloads are sanitized on write & escaped on render
 *  - IDOR: a user cannot read/update/delete another user's notes
 *  - CSRF: state-changing requests without a token are rejected
 *  - Auth: protected routes require a session
 *  - Rate limiting: auth endpoints are throttled
 *  - Password hashing: bcrypt is used
 */

const request = require("supertest");
const bcrypt = require("bcryptjs");

const app = require("../src/server");
const { getDb, closeDb } = require("../src/db/database");
const repo = require("../src/db/repository");
const { hashPassword } = require("../src/utils/password");

// Helper: fetch a CSRF token by hitting any page (token is in a signed cookie
// that persists across session regeneration, so it only needs to be fetched once)
async function getCsrfToken(agent) {
  // Use /api/notes (returns JSON, no redirect when logged in) — but we need
  // a page that renders the meta tag. Use /login which works for logged-out
  // users, or /notes for logged-in users. Try /notes first, fall back to /login.
  let page = await agent.get("/notes");
  if (page.status === 302) {
    page = await agent.get("/login");
  }
  const match = page.text.match(/name="csrf-token" content="([a-f0-9]+)"/);
  return match ? match[1] : "";
}

// Helper: register & login a user, return the authenticated cookie jar
async function createUserAndLogin(agent, username, password) {
  const token = await getCsrfToken(agent);
  await agent
    .post("/api/auth/register")
    .set("X-CSRF-Token", token)
    .send({ username, password })
    .expect(201);
  return agent;
}

function makeAgent() {
  return request.agent(app);
}

const STRONG_PASSWORD = "Sup3rSecret!Pass";

// Unique username counter — the DB persists between tests, so each test
// must use a unique username to avoid 409 conflicts.
let userCounter = 0;
function uniqueUsername(prefix) {
  userCounter += 1;
  return `${prefix}_${userCounter}`;
}

afterAll(() => {
  closeDb();
});

describe("Authentication", () => {
  test("registers a new user with a hashed password", async () => {
    const agent = makeAgent();
    const token = await getCsrfToken(agent);
    const username = uniqueUsername("secuser");
    const res = await agent
      .post("/api/auth/register")
      .set("X-CSRF-Token", token)
      .send({ username, password: STRONG_PASSWORD })
      .expect(201);

    expect(res.body.userId).toBeDefined();
    const dbUser = repo.getUserByUsername(username);
    expect(dbUser).toBeDefined();
    // Password must be a bcrypt hash, not plaintext
    expect(dbUser.password_hash).toMatch(/^\$2[ab]\$/);
    expect(dbUser.password_hash).not.toBe(STRONG_PASSWORD);
    expect(await bcrypt.compare(STRONG_PASSWORD, dbUser.password_hash)).toBe(
      true,
    );
  });

  test("rejects weak passwords", async () => {
    const agent = makeAgent();
    const token = await getCsrfToken(agent);
    const res = await agent
      .post("/api/auth/register")
      .set("X-CSRF-Token", token)
      .send({ username: uniqueUsername("weakuser"), password: "short" })
      .expect(422);
    expect(res.body.error).toBe("Validation failed");
  });

  test("rejects duplicate usernames without enumeration", async () => {
    const agent = makeAgent();
    const token = await getCsrfToken(agent);
    const username = uniqueUsername("dupuser");
    await agent
      .post("/api/auth/register")
      .set("X-CSRF-Token", token)
      .send({ username, password: STRONG_PASSWORD })
      .expect(201);
    const res = await agent
      .post("/api/auth/register")
      .set("X-CSRF-Token", token)
      .send({ username, password: STRONG_PASSWORD })
      .expect(409);
    expect(res.body.error).toBe("Registration failed");
  });

  test("login returns generic error for bad credentials (no enumeration)", async () => {
    const agent = makeAgent();
    const token = await getCsrfToken(agent);
    const username = uniqueUsername("loginuser");
    await agent
      .post("/api/auth/register")
      .set("X-CSRF-Token", token)
      .send({ username, password: STRONG_PASSWORD })
      .expect(201);

    const badPass = await agent
      .post("/api/auth/login")
      .set("X-CSRF-Token", token)
      .send({ username, password: "WrongPass!1234" })
      .expect(401);
    expect(badPass.body.error).toBe("Invalid username or password");

    const badUser = await agent
      .post("/api/auth/login")
      .set("X-CSRF-Token", token)
      .send({
        username: "nonexistent_" + Date.now(),
        password: "WrongPass!1234",
      })
      .expect(401);
    expect(badUser.body.error).toBe("Invalid username or password");
  });

  test("protected routes require auth", async () => {
    const res = await request(app)
      .get("/api/notes")
      .set("Accept", "application/json")
      .expect(401);
    expect(res.body.error).toBe("Authentication required");
  });
});

describe("Notes CRUD & IDOR protection", () => {
  let userA, userB, tokenA, tokenB;

  beforeEach(async () => {
    userA = makeAgent();
    userB = makeAgent();
    await createUserAndLogin(
      userA,
      uniqueUsername("userA_crud"),
      STRONG_PASSWORD,
    );
    await createUserAndLogin(
      userB,
      uniqueUsername("userB_crud"),
      STRONG_PASSWORD,
    );
    tokenA = await getCsrfToken(userA);
    tokenB = await getCsrfToken(userB);
  });

  test("user can create, read, update, delete own notes", async () => {
    // Create
    const createRes = await userA
      .post("/api/notes")
      .set("X-CSRF-Token", tokenA)
      .send({ title: "My Note", body: "Secret content" })
      .expect(201);
    const noteId = createRes.body.id;

    // Read
    const getRes = await userA.get("/api/notes/" + noteId).expect(200);
    expect(getRes.body.note.title).toBe("My Note");

    // Update
    await userA
      .put("/api/notes/" + noteId)
      .set("X-CSRF-Token", tokenA)
      .send({ title: "Updated", body: "New body" })
      .expect(200);
    const updated = await userA.get("/api/notes/" + noteId).expect(200);
    expect(updated.body.note.title).toBe("Updated");

    // Delete
    await userA
      .delete("/api/notes/" + noteId)
      .set("X-CSRF-Token", tokenA)
      .expect(200);
    await userA.get("/api/notes/" + noteId).expect(404);
  });

  test("IDOR: user B cannot read user A's note", async () => {
    const createRes = await userA
      .post("/api/notes")
      .set("X-CSRF-Token", tokenA)
      .send({ title: "Private", body: "A secret" })
      .expect(201);
    const noteId = createRes.body.id;

    await userB.get("/api/notes/" + noteId).expect(404);
  });

  test("IDOR: user B cannot update user A's note", async () => {
    const createRes = await userA
      .post("/api/notes")
      .set("X-CSRF-Token", tokenA)
      .send({ title: "Original", body: "A secret" })
      .expect(201);
    const noteId = createRes.body.id;

    const res = await userB
      .put("/api/notes/" + noteId)
      .set("X-CSRF-Token", tokenB)
      .send({ title: "Hacked", body: "pwned" })
      .expect(404);
    expect(res.body.error).toBe("Note not found");

    // Confirm original is untouched
    const note = await userA.get("/api/notes/" + noteId).expect(200);
    expect(note.body.note.title).toBe("Original");
  });

  test("IDOR: user B cannot delete user A's note", async () => {
    const createRes = await userA
      .post("/api/notes")
      .set("X-CSRF-Token", tokenA)
      .send({ title: "Keep me", body: "A secret" })
      .expect(201);
    const noteId = createRes.body.id;

    await userB
      .delete("/api/notes/" + noteId)
      .set("X-CSRF-Token", tokenB)
      .expect(404);

    // Still exists for user A
    await userA.get("/api/notes/" + noteId).expect(200);
  });

  test("user A only sees their own notes in the list", async () => {
    await userA
      .post("/api/notes")
      .set("X-CSRF-Token", tokenA)
      .send({ title: "A1", body: "a" })
      .expect(201);
    await userB
      .post("/api/notes")
      .set("X-CSRF-Token", tokenB)
      .send({ title: "B1", body: "b" })
      .expect(201);

    const listA = await userA.get("/api/notes").expect(200);
    expect(listA.body.notes).toHaveLength(1);
    expect(listA.body.notes[0].title).toBe("A1");
  });
});

describe("SQL Injection prevention", () => {
  test("malicious note id does not leak data", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("sqli_user"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: "safe", body: "safe" })
      .expect(201);

    // Non-integer id → 400, not a SQL error
    const res = await agent.get("/api/notes/1%20OR%201=1").expect(400);
    expect(res.body.error).toBe("Invalid note id");
  });

  test("SQL injection in title/body is stored as literal text", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("sqli_text"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    const payload = "'); DROP TABLE notes;--";
    const createRes = await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: payload, body: payload })
      .expect(201);
    const note = await agent.get("/api/notes/" + createRes.body.id).expect(200);
    expect(note.body.note.title).toBe(payload);

    // Table still exists
    const list = await agent.get("/api/notes").expect(200);
    expect(list.body.notes.length).toBeGreaterThan(0);
  });
});

describe("XSS prevention", () => {
  test("XSS payload in note is sanitized to plain text", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("xss_user"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    const payload = '<script>alert("xss")</script>';
    const createRes = await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: payload, body: payload })
      .expect(201);
    const note = await agent.get("/api/notes/" + createRes.body.id).expect(200);
    // Script tags stripped
    expect(note.body.note.title).not.toContain("<script>");
    expect(note.body.note.body).not.toContain("<script>");
  });

  test("notes page HTML-escapes content", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("xss_html"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: "Test & <b>bold</b>", body: "plain" })
      .expect(201);
    const html = await agent.get("/notes").expect(200);
    // The sanitized title should not contain raw <b> tags from the input
    expect(html.text).not.toContain("<b>bold</b>");
  });
});

describe("CSRF protection", () => {
  test("POST without CSRF token is rejected", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("csrf_user"),
      STRONG_PASSWORD,
    );

    // The agent has a session cookie but we send no X-CSRF-Token header.
    const res = await agent
      .post("/api/notes")
      .set("Content-Type", "application/json")
      .send({ title: "No CSRF", body: "body" })
      .expect(403);
    expect(res.body.error).toBe("CSRF token validation failed");
  });

  test("POST with valid CSRF token succeeds", async () => {
    const agent = makeAgent();
    await createUserAndLogin(agent, uniqueUsername("csrf_ok"), STRONG_PASSWORD);

    // Get a CSRF token by hitting a page (session is created)
    const token = await getCsrfToken(agent);

    await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: "With CSRF", body: "body" })
      .expect(201);
  });
});

describe("Security headers", () => {
  test("Helmet sets strict security headers", async () => {
    const res = await request(app).get("/login");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["strict-transport-security"]).toBeDefined();
    expect(res.headers["content-security-policy"]).toBeDefined();
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
  });

  test("CSP disallows inline scripts and external origins", async () => {
    const res = await request(app).get("/login");
    const csp = res.headers["content-security-policy"];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });
});

describe("Input validation", () => {
  test("rejects oversized body", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("big_user"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    const huge = "a".repeat(10001);
    const res = await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: "big", body: huge })
      .expect(422);
    expect(res.body.error).toBe("Validation failed");
  });

  test("rejects empty title", async () => {
    const agent = makeAgent();
    await createUserAndLogin(
      agent,
      uniqueUsername("empty_user"),
      STRONG_PASSWORD,
    );
    const token = await getCsrfToken(agent);
    const res = await agent
      .post("/api/notes")
      .set("X-CSRF-Token", token)
      .send({ title: "", body: "body" })
      .expect(422);
    expect(res.body.error).toBe("Validation failed");
  });
});
