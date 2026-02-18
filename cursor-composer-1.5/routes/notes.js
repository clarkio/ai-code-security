/**
 * Notes routes - CRUD with authorization and validation
 */
import { Router } from 'express';
import { body, param, validationResult } from 'express-validator';
import {
  getNotesByUserId,
  getNoteById,
  createNote,
  updateNote,
  deleteNote,
} from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const MAX_TITLE_LENGTH = 200;
const MAX_CONTENT_LENGTH = 10000;

const noteValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: MAX_TITLE_LENGTH })
    .withMessage(`Title must be at most ${MAX_TITLE_LENGTH} characters`),
  body('content')
    .trim()
    .isLength({ max: MAX_CONTENT_LENGTH })
    .withMessage(`Content must be at most ${MAX_CONTENT_LENGTH} characters`),
];

const idParamValidation = [
  param('id').isInt({ min: 1 }).withMessage('Invalid note ID'),
];

router.get('/', requireAuth, (req, res) => {
  const notes = getNotesByUserId(req.session.userId);
  res.render('notes-list', {
    title: 'My Notes',
    notes,
    csrfToken: req.csrfToken?.(),
  });
});

router.get('/new', requireAuth, (req, res) => {
  res.render('note-form', {
    title: 'New Note',
    note: null,
    csrfToken: req.csrfToken?.(),
  });
});

router.get('/:id/edit', requireAuth, idParamValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.redirect('/');
  }

  const note = getNoteById(parseInt(req.params.id, 10), req.session.userId);
  if (!note) {
    return res.status(404).render('error', { message: 'Note not found' });
  }

  res.render('note-form', {
    title: 'Edit Note',
    note,
    csrfToken: req.csrfToken?.(),
  });
});

router.post('/', requireAuth, noteValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('note-form', {
      title: 'New Note',
      note: { title: req.body.title, content: req.body.content },
      csrfToken: req.csrfToken?.(),
      errors: errors.array(),
    });
  }

  const title = req.body.title.trim();
  const content = req.body.content.trim();
  const id = createNote(req.session.userId, title, content);
  res.redirect(`/notes/${id}`);
});

router.get('/:id', requireAuth, idParamValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.redirect('/');
  }

  const note = getNoteById(parseInt(req.params.id, 10), req.session.userId);
  if (!note) {
    return res.status(404).render('error', { message: 'Note not found' });
  }

  res.render('note-view', { title: note.title, note, csrfToken: req.csrfToken?.() });
});

router.post('/:id', requireAuth, idParamValidation, noteValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const note = getNoteById(parseInt(req.params.id, 10), req.session.userId);
    if (!note) return res.redirect('/');
    return res.status(400).render('note-form', {
      title: 'Edit Note',
      note: { ...note, title: req.body.title, content: req.body.content },
      csrfToken: req.csrfToken?.(),
      errors: errors.array(),
    });
  }

  const noteId = parseInt(req.params.id, 10);
  const title = req.body.title.trim();
  const content = req.body.content.trim();
  const updated = updateNote(noteId, req.session.userId, title, content);

  if (updated === 0) {
    return res.status(404).render('error', { message: 'Note not found' });
  }

  res.redirect(`/notes/${noteId}`);
});

router.post('/:id/delete', requireAuth, idParamValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.redirect('/');
  }

  const deleted = deleteNote(parseInt(req.params.id, 10), req.session.userId);
  if (deleted === 0) {
    return res.status(404).render('error', { message: 'Note not found' });
  }

  res.redirect('/');
});

export default router;
