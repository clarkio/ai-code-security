import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from '../config.js';

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_updated ON notes(user_id, updated_at DESC);
`;

/** @type {DatabaseSync | null} */
let db = null;

export function getDb() {
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db;
}

export function initDb() {
  const dir = path.dirname(config.databasePath);
  fs.mkdirSync(dir, { recursive: true });

  db = new DatabaseSync(config.databasePath);
  db.exec(SCHEMA);
  return db;
}

/** @param {string} email */
export function findUserByEmail(email) {
  const row = getDb()
    .prepare('SELECT id, email, password_hash FROM users WHERE email = ?')
    .get(email.trim().toLowerCase());
  return row ?? null;
}

/** @param {string} email @param {string} passwordHash */
export function createUser(email, passwordHash) {
  const info = getDb()
    .prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
    .run(email.trim().toLowerCase(), passwordHash);
  return info.lastInsertRowid;
}

/** @param {number} userId */
export function listNotesForUser(userId) {
  return getDb()
    .prepare(
      `SELECT id, title, body, created_at, updated_at FROM notes
       WHERE user_id = ? ORDER BY updated_at DESC`
    )
    .all(userId);
}

/** @param {number} userId @param {number} noteId */
export function getNoteForUser(userId, noteId) {
  return getDb()
    .prepare(
      `SELECT id, title, body, created_at, updated_at FROM notes
       WHERE user_id = ? AND id = ?`
    )
    .get(userId, noteId);
}

/** @param {number} userId @param {string} title @param {string} body */
export function createNote(userId, title, body) {
  const info = getDb()
    .prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)')
    .run(userId, title, body);
  return info.lastInsertRowid;
}

/** @param {number} userId @param {number} noteId @param {string} title @param {string} body */
export function updateNote(userId, noteId, title, body) {
  const info = getDb()
    .prepare(
      `UPDATE notes SET title = ?, body = ?, updated_at = datetime('now')
       WHERE user_id = ? AND id = ?`
    )
    .run(title, body, userId, noteId);
  return info.changes;
}

/** @param {number} userId @param {number} noteId */
export function deleteNote(userId, noteId) {
  const info = getDb()
    .prepare('DELETE FROM notes WHERE user_id = ? AND id = ?')
    .run(userId, noteId);
  return info.changes;
}
