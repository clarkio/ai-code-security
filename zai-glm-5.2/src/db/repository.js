"use strict";

/**
 * Data access layer.
 *
 * SECURITY: Every note query is scoped by user_id so a user can NEVER read or
 * modify another user's notes — even if they guess the note id (IDOR protection).
 * All inputs are passed as bound parameters (SQL injection protection).
 */

const { getDb } = require("./database");

// --- Users ---

function createUser(username, passwordHash) {
  const db = getDb();
  const stmt = db.prepare(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
  );
  const info = stmt.run(username, passwordHash);
  return info.lastInsertRowid;
}

function getUserByUsername(username) {
  const db = getDb();
  return db
    .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
    .get(username);
}

function getUserById(id) {
  const db = getDb();
  return db.prepare("SELECT id, username FROM users WHERE id = ?").get(id);
}

// --- Notes ---

/**
 * List all notes belonging to a user.
 * user_id is ALWAYS bound — no global listing is possible.
 */
function listNotes(userId) {
  const db = getDb();
  return db
    .prepare(
      "SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC",
    )
    .all(userId);
}

/**
 * Get a single note. The WHERE clause includes user_id so a user can only
 * fetch their own notes — this is the core IDOR defense.
 */
function getNote(userId, noteId) {
  const db = getDb();
  return db
    .prepare(
      "SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
    )
    .get(noteId, userId);
}

function createNote(userId, title, body) {
  const db = getDb();
  const stmt = db.prepare(
    "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
  );
  const info = stmt.run(userId, title, body);
  return info.lastInsertRowid;
}

function updateNote(userId, noteId, title, body) {
  const db = getDb();
  // user_id in WHERE ensures ownership check at the DB level
  const stmt = db.prepare(
    `UPDATE notes
       SET title = ?, body = ?, updated_at = datetime('now')
     WHERE id = ? AND user_id = ?`,
  );
  const info = stmt.run(title, body, noteId, userId);
  return info.changes > 0;
}

function deleteNote(userId, noteId) {
  const db = getDb();
  const stmt = db.prepare("DELETE FROM notes WHERE id = ? AND user_id = ?");
  const info = stmt.run(noteId, userId);
  return info.changes > 0;
}

module.exports = {
  createUser,
  getUserByUsername,
  getUserById,
  listNotes,
  getNote,
  createNote,
  updateNote,
  deleteNote,
};
