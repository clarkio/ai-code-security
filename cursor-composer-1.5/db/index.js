/**
 * Database layer - ALL queries use parameterized statements to prevent SQL injection
 * Uses sql.js (pure JavaScript, no native bindings)
 */
import initSqlJs from 'sql.js';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';
import { config } from '../config.js';

let db = null;

async function ensureDb() {
  if (db) return db;
  const SQL = await initSqlJs();
  const dbDir = dirname(config.databasePath);
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
  }
  if (existsSync(config.databasePath)) {
    const buf = readFileSync(config.databasePath);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }
  return db;
}

function save() {
  if (db) {
    const data = db.export();
    writeFileSync(config.databasePath, Buffer.from(data));
  }
}

export async function initDb() {
  return ensureDb();
}

// --- Users ---

export function createUser(username, passwordHash) {
  db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, passwordHash]);
  const r = db.exec('SELECT last_insert_rowid() as id');
  const id = r[0]?.values?.[0]?.[0] ?? 0;
  save();
  return id;
}

export function getUserByUsername(username) {
  const stmt = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
  stmt.bind([username]);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

export function getUserById(id) {
  const stmt = db.prepare('SELECT id, username FROM users WHERE id = ?');
  stmt.bind([id]);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

// --- Notes ---

export function getNotesByUserId(userId) {
  const stmt = db.prepare(
    'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC'
  );
  stmt.bind([userId]);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

export function getNoteById(noteId, userId) {
  const stmt = db.prepare(
    'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?'
  );
  stmt.bind([noteId, userId]);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

export function createNote(userId, title, content) {
  db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', [userId, title, content]);
  const r = db.exec('SELECT last_insert_rowid() as id');
  const id = r[0]?.values?.[0]?.[0] ?? 0;
  save();
  return id;
}

export function updateNote(noteId, userId, title, content) {
  db.run(
    "UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
    [title, content, noteId, userId]
  );
  const r = db.exec('SELECT changes() as c');
  const changes = r[0]?.values?.[0]?.[0] ?? 0;
  save();
  return changes;
}

export function deleteNote(noteId, userId) {
  db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [noteId, userId]);
  const r = db.exec('SELECT changes() as c');
  const changes = r[0]?.values?.[0]?.[0] ?? 0;
  save();
  return changes;
}
