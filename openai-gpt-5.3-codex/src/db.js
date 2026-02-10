import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import initSqlJs from "sql.js";
import { config } from "./config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sqlJsDistDir = path.join(__dirname, "..", "node_modules", "sql.js", "dist");
const dbPath = config.dbPath === ":memory:" ? ":memory:" : path.resolve(config.dbPath);

let db = null;
let initialized = false;

function ensureReady() {
  if (!db) {
    throw new Error("Database is not initialized.");
  }
}

function persistIfNeeded() {
  if (dbPath === ":memory:") {
    return;
  }
  const data = db.export();
  fs.writeFileSync(dbPath, Buffer.from(data));
}

function queryAll(sql, params = []) {
  ensureReady();
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    return rows;
  } finally {
    stmt.free();
  }
}

function queryOne(sql, params = []) {
  const rows = queryAll(sql, params);
  return rows[0] ?? null;
}

export async function initDb() {
  if (initialized) {
    return;
  }

  if (dbPath !== ":memory:") {
    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true });
  }

  const SQL = await initSqlJs({
    locateFile: (file) => path.join(sqlJsDistDir, file),
  });

  if (dbPath !== ":memory:" && fs.existsSync(dbPath)) {
    const fileData = fs.readFileSync(dbPath);
    db = new SQL.Database(fileData);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  persistIfNeeded();
  initialized = true;
}

export function listNotes(limit, offset) {
  return queryAll(
    `
      SELECT id, title, content, created_at, updated_at
      FROM notes
      ORDER BY updated_at DESC
      LIMIT ? OFFSET ?
    `,
    [limit, offset],
  );
}

export function getNoteById(id) {
  return queryOne(
    `
      SELECT id, title, content, created_at, updated_at
      FROM notes
      WHERE id = ?
    `,
    [id],
  );
}

export function createNote({ title, content }) {
  ensureReady();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.run(
    `
      INSERT INTO notes (id, title, content, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `,
    [id, title, content, now, now],
  );
  persistIfNeeded();
  return getNoteById(id);
}

export function updateNote(id, { title, content }) {
  ensureReady();
  const existing = getNoteById(id);
  if (!existing) {
    return null;
  }

  const now = new Date().toISOString();
  db.run(
    `
      UPDATE notes
      SET title = ?, content = ?, updated_at = ?
      WHERE id = ?
    `,
    [title, content, now, id],
  );
  persistIfNeeded();
  return getNoteById(id);
}

export function deleteNote(id) {
  ensureReady();
  const existing = getNoteById(id);
  if (!existing) {
    return false;
  }

  db.run(
    `
      DELETE FROM notes
      WHERE id = ?
    `,
    [id],
  );
  persistIfNeeded();
  return true;
}

export function closeDb() {
  if (!db) {
    return;
  }
  persistIfNeeded();
  db.close();
  db = null;
  initialized = false;
}
