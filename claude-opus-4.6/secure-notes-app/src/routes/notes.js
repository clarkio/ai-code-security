const express = require('express');
const { queries } = require('../database');
const { requireLogin, requireNoteOwner } = require('../middleware/auth');
const { getErrors, noteRules } = require('../middleware/validate');

const router = express.Router();

// All notes routes require authentication
router.use(requireLogin);

// --- List notes + show create form ---
router.get('/', (req, res) => {
  const notes = queries.getNotesByUser(req.session.userId);
  res.render('notes', { notes, errors: null, editNote: null });
});

// --- Create note ---
router.post('/notes', noteRules, (req, res) => {
  const errors = getErrors(req);
  if (errors) {
    const notes = queries.getNotesByUser(req.session.userId);
    return res.status(400).render('notes', { notes, errors, editNote: null });
  }

  const { title, content } = req.body;
  queries.createNote(req.session.userId, title, content);
  res.redirect('/');
});

// --- Show edit form ---
router.get('/notes/:id/edit', requireNoteOwner, (req, res) => {
  const notes = queries.getNotesByUser(req.session.userId);
  res.render('notes', { notes, errors: null, editNote: req.note });
});

// --- Update note ---
router.post('/notes/:id/edit', requireNoteOwner, noteRules, (req, res) => {
  const errors = getErrors(req);
  if (errors) {
    const notes = queries.getNotesByUser(req.session.userId);
    return res.status(400).render('notes', { notes, errors, editNote: req.note });
  }

  const { title, content } = req.body;
  // user_id in WHERE clause ensures ownership even if middleware is bypassed
  queries.updateNote(title, content, req.note.id, req.session.userId);
  res.redirect('/');
});

// --- Delete note ---
router.post('/notes/:id/delete', requireNoteOwner, (req, res) => {
  // user_id in WHERE clause ensures ownership even if middleware is bypassed
  queries.deleteNote(req.note.id, req.session.userId);
  res.redirect('/');
});

module.exports = router;
