'use strict';

const db = require('../db');

// Every statement that touches a specific note is scoped by user_id as well as
// note id. This makes Insecure Direct Object Reference (IDOR) attacks
// impossible: a user can never read or mutate a note they don't own, even if
// they guess another note's id.
const insertNote = db.prepare(
  'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)'
);
const selectNotesByUser = db.prepare(
  'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC'
);
const selectNoteForUser = db.prepare(
  'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?'
);
const updateNoteForUser = db.prepare(
  "UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?"
);
const deleteNoteForUser = db.prepare(
  'DELETE FROM notes WHERE id = ? AND user_id = ?'
);

function createNote(userId, title, content) {
  const info = insertNote.run(userId, title, content);
  return { id: info.lastInsertRowid };
}

function listNotes(userId) {
  return selectNotesByUser.all(userId);
}

function getNote(userId, noteId) {
  return selectNoteForUser.get(noteId, userId) || null;
}

/** @returns {boolean} true if a note was actually updated (owned by user). */
function updateNote(userId, noteId, title, content) {
  const info = updateNoteForUser.run(title, content, noteId, userId);
  return info.changes > 0;
}

/** @returns {boolean} true if a note was actually deleted (owned by user). */
function deleteNote(userId, noteId) {
  const info = deleteNoteForUser.run(noteId, userId);
  return info.changes > 0;
}

module.exports = { createNote, listNotes, getNote, updateNote, deleteNote };
