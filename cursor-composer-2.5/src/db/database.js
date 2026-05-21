import Database from 'better-sqlite3';
import { config } from '../config.js';

const db = new Database(config.databasePath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function getUserByUsername(username) {
  return db
    .prepare('SELECT id, username, password_hash FROM users WHERE username = ?')
    .get(username);
}

export function getUserById(id) {
  return db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
}

export function createUser(username, passwordHash) {
  const result = db
    .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(username, passwordHash);
  return result.lastInsertRowid;
}

export function listNotesForUser(userId) {
  return db
    .prepare(
      `SELECT id, title, body, created_at, updated_at
       FROM notes
       WHERE user_id = ?
       ORDER BY updated_at DESC`
    )
    .all(userId);
}

export function getNoteForUser(noteId, userId) {
  return db
    .prepare(
      `SELECT id, title, body, created_at, updated_at
       FROM notes
       WHERE id = ? AND user_id = ?`
    )
    .get(noteId, userId);
}

export function createNote(userId, title, body) {
  const result = db
    .prepare(
      `INSERT INTO notes (user_id, title, body)
       VALUES (?, ?, ?)`
    )
    .run(userId, title, body);
  return result.lastInsertRowid;
}

export function updateNote(noteId, userId, title, body) {
  const result = db
    .prepare(
      `UPDATE notes
       SET title = ?, body = ?, updated_at = datetime('now')
       WHERE id = ? AND user_id = ?`
    )
    .run(title, body, noteId, userId);
  return result.changes > 0;
}

export function deleteNote(noteId, userId) {
  const result = db
    .prepare('DELETE FROM notes WHERE id = ? AND user_id = ?')
    .run(noteId, userId);
  return result.changes > 0;
}

export function closeDatabase() {
  db.close();
}
