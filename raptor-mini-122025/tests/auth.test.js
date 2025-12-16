const request = require("supertest");
const knexLib = require("knex");
const knexConfig = require("../knexfile");
const appFactory = require("../src/index");

let knex;
let app;

beforeAll(async () => {
  knex = knexLib({
    ...knexConfig,
    connection:
      process.env.DATABASE_URL ||
      "postgresql://postgres:postgres@localhost:5432/notesdb",
  });
  app = appFactory;
  // You may want to run a local test DB or a test container for reliable tests.
});

afterAll(async () => {
  await knex.destroy();
});

describe("auth", () => {
  test("registration and login flow", async () => {
    const username = `testuser${Date.now()}`;
    const password = "A-very-strong-passw0rd!";

    const register = await request(app)
      .post("/api/auth/register")
      .send({ username, password });
    expect(register.status).toBe(201);

    const login = await request(app)
      .post("/api/auth/login")
      .send({ username, password });
    expect(login.status).toBe(200);
  });
});
