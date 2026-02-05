const { queries } = require('../database');

/**
 * Redirects unauthenticated users to the login page.
 */
function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

/**
 * Validates that the note in req.params.id belongs to the logged-in user.
 * Prevents IDOR (Insecure Direct Object Reference) attacks.
 */
function requireNoteOwner(req, res, next) {
  const noteId = Number(req.params.id);
  if (!Number.isInteger(noteId) || noteId <= 0) {
    return res.status(400).send('Invalid note ID');
  }

  const note = queries.getNoteById(noteId);
  if (!note) {
    return res.status(404).send('Note not found');
  }
  if (note.user_id !== req.session.userId) {
    return res.status(403).send('Forbidden');
  }

  req.note = note;
  next();
}

module.exports = { requireLogin, requireNoteOwner };
