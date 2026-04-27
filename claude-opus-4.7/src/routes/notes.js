'use strict';

const express = require('express');

const db = require('../db');
const { noteSchema, idSchema } = require('../validators');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Every route below is gated by requireAuth; every DB call binds user_id so
// that ownership is enforced at the row level.
router.use(requireAuth);

router.get('/', (req, res) => {
  const notes = db.listNotesByUser(req.user.id);
  res.render('notes/index', { title: 'My notes', notes });
});

router.get('/new', (req, res) => {
  res.render('notes/new', {
    title: 'New note',
    error: null,
    values: { title: '', body: '' },
  });
});

router.post('/', (req, res, next) => {
  const parsed = noteSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).render('notes/new', {
      title: 'New note',
      error: 'Title is required and must fit the size limits.',
      values: {
        title: typeof req.body.title === 'string' ? req.body.title : '',
        body: typeof req.body.body === 'string' ? req.body.body : '',
      },
    });
  }
  try {
    db.createNote(req.user.id, parsed.data.title, parsed.data.body);
    res.redirect('/notes');
  } catch (err) {
    next(err);
  }
});

function parseIdParam(req, res) {
  const parsed = idSchema.safeParse(req.params.id);
  if (!parsed.success) {
    res.status(404).render('error', {
      title: 'Not found',
      status: 404,
      message: 'Note not found.',
    });
    return null;
  }
  return parsed.data;
}

router.get('/:id/edit', (req, res) => {
  const id = parseIdParam(req, res);
  if (id === null) return;
  const note = db.getNoteForUser(id, req.user.id);
  if (!note) {
    return res.status(404).render('error', {
      title: 'Not found',
      status: 404,
      message: 'Note not found.',
    });
  }
  res.render('notes/edit', { title: 'Edit note', note, error: null });
});

router.post('/:id', (req, res, next) => {
  const id = parseIdParam(req, res);
  if (id === null) return;

  const parsed = noteSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).render('notes/edit', {
      title: 'Edit note',
      note: {
        id,
        title: typeof req.body.title === 'string' ? req.body.title : '',
        body: typeof req.body.body === 'string' ? req.body.body : '',
      },
      error: 'Title is required and must fit the size limits.',
    });
  }
  try {
    const result = db.updateNote(id, req.user.id, parsed.data.title, parsed.data.body);
    if (result.changes === 0) {
      return res.status(404).render('error', {
        title: 'Not found',
        status: 404,
        message: 'Note not found.',
      });
    }
    res.redirect('/notes');
  } catch (err) {
    next(err);
  }
});

router.post('/:id/delete', (req, res, next) => {
  const id = parseIdParam(req, res);
  if (id === null) return;
  try {
    const result = db.deleteNote(id, req.user.id);
    if (result.changes === 0) {
      return res.status(404).render('error', {
        title: 'Not found',
        status: 404,
        message: 'Note not found.',
      });
    }
    res.redirect('/notes');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
