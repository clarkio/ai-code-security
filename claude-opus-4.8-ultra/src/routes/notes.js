'use strict';

const express = require('express');
const noteModel = require('../models/noteModel');
const { requireAuth } = require('../middleware/security');
const { noteSchema, noteIdSchema } = require('../validators');

const router = express.Router();

// Every route in this router requires authentication.
router.use(requireAuth);

// List all of the current user's notes (also the "create" surface).
router.get('/', (req, res) => {
  const notes = noteModel.listNotes(req.session.userId);
  res.render('notes/index', { title: 'My Notes', notes });
});

// Create a note.
router.post('/', (req, res) => {
  const parsed = noteSchema.safeParse(req.body);
  if (!parsed.success) {
    const notes = noteModel.listNotes(req.session.userId);
    return res.status(400).render('notes/index', {
      title: 'My Notes',
      notes,
      errors: parsed.error.issues.map((i) => i.message),
      values: { title: req.body.title || '', content: req.body.content || '' },
    });
  }
  const { title, content } = parsed.data;
  noteModel.createNote(req.session.userId, title, content);
  return res.redirect('/notes');
});

// Helper: parse + validate the :id param, returning a number or null.
function parseNoteId(raw) {
  const parsed = noteIdSchema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

// Show the edit form for one note.
router.get('/:id/edit', (req, res) => {
  const noteId = parseNoteId(req.params.id);
  if (noteId === null) return res.status(404).render('error', notFound());

  const note = noteModel.getNote(req.session.userId, noteId);
  if (!note) return res.status(404).render('error', notFound());

  res.render('notes/edit', { title: 'Edit Note', note, errors: [] });
});

// Update a note.
router.post('/:id', (req, res) => {
  const noteId = parseNoteId(req.params.id);
  if (noteId === null) return res.status(404).render('error', notFound());

  const parsed = noteSchema.safeParse(req.body);
  if (!parsed.success) {
    const note = noteModel.getNote(req.session.userId, noteId);
    if (!note) return res.status(404).render('error', notFound());
    return res.status(400).render('notes/edit', {
      title: 'Edit Note',
      note: { ...note, title: req.body.title, content: req.body.content },
      errors: parsed.error.issues.map((i) => i.message),
    });
  }

  const { title, content } = parsed.data;
  const updated = noteModel.updateNote(req.session.userId, noteId, title, content);
  if (!updated) return res.status(404).render('error', notFound());

  return res.redirect('/notes');
});

// Delete a note.
router.post('/:id/delete', (req, res) => {
  const noteId = parseNoteId(req.params.id);
  if (noteId === null) return res.status(404).render('error', notFound());

  noteModel.deleteNote(req.session.userId, noteId);
  return res.redirect('/notes');
});

function notFound() {
  return { title: 'Not Found', message: 'That note does not exist.' };
}

module.exports = router;
