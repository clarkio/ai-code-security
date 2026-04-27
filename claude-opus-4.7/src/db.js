'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const config = require('./config');

const dir = path.dirname(config.databasePath);
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

const db = new Database(config.databasePath);

// Pragmas: enforce FKs, durable WAL, sane busy timeout.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes (user_id);
`);

// All queries below are prepared statements with bound parameters — never
// string-concatenate SQL.
const stmts = {
  insertUser: db.prepare(
    'INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id, username',
  ),
  findUserByUsername: db.prepare(
    'SELECT id, username, password_hash FROM users WHERE username = ?',
  ),
  findUserById: db.prepare('SELECT id, username FROM users WHERE id = ?'),

  listNotesByUser: db.prepare(
    `SELECT id, title, body, created_at, updated_at
     FROM notes
     WHERE user_id = ?
     ORDER BY updated_at DESC, id DESC`,
  ),
  getNoteForUser: db.prepare(
    'SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?',
  ),
  insertNote: db.prepare(
    `INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)
     RETURNING id`,
  ),
  // The "user_id = ?" predicate enforces ownership at the SQL layer — even if
  // an authorization bug ever sneaks in upstream, the row will not be touched.
  updateNote: db.prepare(
    `UPDATE notes
       SET title = ?, body = ?, updated_at = unixepoch()
     WHERE id = ? AND user_id = ?`,
  ),
  deleteNote: db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?'),
};

function createUser(username, passwordHash) {
  return stmts.insertUser.get(username, passwordHash);
}

function findUserByUsername(username) {
  return stmts.findUserByUsername.get(username);
}

function findUserById(id) {
  return stmts.findUserById.get(id);
}

function listNotesByUser(userId) {
  return stmts.listNotesByUser.all(userId);
}

function getNoteForUser(noteId, userId) {
  return stmts.getNoteForUser.get(noteId, userId);
}

function createNote(userId, title, body) {
  return stmts.insertNote.get(userId, title, body);
}

function updateNote(noteId, userId, title, body) {
  return stmts.updateNote.run(title, body, noteId, userId);
}

function deleteNote(noteId, userId) {
  return stmts.deleteNote.run(noteId, userId);
}

module.exports = {
  db,
  createUser,
  findUserByUsername,
  findUserById,
  listNotesByUser,
  getNoteForUser,
  createNote,
  updateNote,
  deleteNote,
};
