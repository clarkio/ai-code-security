import Database from 'better-sqlite3';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DATABASE_PATH || join(__dirname, '..', 'data', 'notes.db');

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function getUserById(id) {
  const stmt = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?');
  return stmt.get(id);
}

export function getUserByUsername(username) {
  const stmt = db.prepare('SELECT id, username, email, password_hash FROM users WHERE username = ?');
  return stmt.get(username);
}

export function getUserByEmail(email) {
  const stmt = db.prepare('SELECT id, username, email FROM users WHERE email = ?');
  return stmt.get(email);
}

export function createUser(username, email, passwordHash) {
  const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
  const result = stmt.run(username, email, passwordHash);
  return getUserById(result.lastInsertRowid);
}

export function createNote(userId, title, content) {
  const stmt = db.prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)');
  const result = stmt.run(userId, title, content);
  return getNoteById(result.lastInsertRowid);
}

export function getNoteById(id) {
  const stmt = db.prepare('SELECT id, user_id, title, content, created_at, updated_at FROM notes WHERE id = ?');
  return stmt.get(id);
}

export function getNotesByUserId(userId, limit = 50, offset = 0) {
  const stmt = db.prepare(`
    SELECT id, user_id, title, content, created_at, updated_at 
    FROM notes 
    WHERE user_id = ? 
    ORDER BY updated_at DESC 
    LIMIT ? OFFSET ?
  `);
  return stmt.all(userId, limit, offset);
}

export function updateNote(id, userId, title, content) {
  const stmt = db.prepare(`
    UPDATE notes 
    SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP 
    WHERE id = ? AND user_id = ?
  `);
  const result = stmt.run(title, content, id, userId);
  if (result.changes === 0) {
    return null;
  }
  return getNoteById(id);
}

export function deleteNote(id, userId) {
  const stmt = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
  const result = stmt.run(id, userId);
  return result.changes > 0;
}

export function countNotesByUserId(userId) {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM notes WHERE user_id = ?');
  const result = stmt.get(userId);
  return result.count;
}

export default db;
