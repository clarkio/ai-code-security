import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import {
  listNotesForUser,
  getNoteForUser,
  createNote,
  updateNote,
  deleteNote,
} from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';
export const notesRouter = Router();

notesRouter.use(requireAuth);

const noteValidators = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 200 })
    .withMessage('Title is too long'),
  body('body')
    .isString()
    .isLength({ min: 0, max: 50_000 })
    .withMessage('Note body is too long'),
];

/** @param {unknown} raw */
function parsePositiveIntId(raw) {
  const id = Number.parseInt(String(raw), 10);
  if (!Number.isInteger(id) || id < 1) {
    return null;
  }
  return id;
}

function stripNullBytes(s) {
  return String(s).replace(/\0/g, '');
}

notesRouter.get('/', (req, res) => {
  const notes = listNotesForUser(req.session.userId);
  res.render('notes/list', { title: 'Notes', notes });
});

notesRouter.get('/new', (req, res) => {
  res.render('notes/new', { title: 'New note', error: null });
});

notesRouter.post('/', noteValidators, (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('notes/new', {
        title: 'New note',
        error: errors.array()[0]?.msg || 'Invalid input',
      });
    }
    const title = stripNullBytes(req.body.title);
    const bodyText = stripNullBytes(req.body.body);
    createNote(req.session.userId, title, bodyText);
    res.redirect('/notes');
  } catch (e) {
    next(e);
  }
});

notesRouter.get('/:id/edit', (req, res, next) => {
  try {
    const noteId = parsePositiveIntId(req.params.id);
    if (noteId === null) {
      return res.status(404).type('html').send('Not found');
    }
    const note = getNoteForUser(req.session.userId, noteId);
    if (!note) {
      return res.status(404).type('html').send('Not found');
    }
    res.render('notes/edit', { title: 'Edit note', note, error: null });
  } catch (e) {
    next(e);
  }
});

notesRouter.post('/:id/delete', (req, res, next) => {
  try {
    const noteId = parsePositiveIntId(req.params.id);
    if (noteId === null) {
      return res.status(404).type('html').send('Not found');
    }
    const removed = deleteNote(req.session.userId, noteId);
    if (!removed) {
      return res.status(404).type('html').send('Not found');
    }
    res.redirect('/notes');
  } catch (e) {
    next(e);
  }
});

notesRouter.post('/:id', noteValidators, (req, res, next) => {
  try {
    const noteId = parsePositiveIntId(req.params.id);
    if (noteId === null) {
      return res.status(404).type('html').send('Not found');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const note = getNoteForUser(req.session.userId, noteId);
      if (!note) {
        return res.status(404).type('html').send('Not found');
      }
      return res.status(400).render('notes/edit', {
        title: 'Edit note',
        note,
        error: errors.array()[0]?.msg || 'Invalid input',
      });
    }
    const title = stripNullBytes(req.body.title);
    const bodyText = stripNullBytes(req.body.body);
    const changed = updateNote(req.session.userId, noteId, title, bodyText);
    if (!changed) {
      return res.status(404).type('html').send('Not found');
    }
    res.redirect('/notes');
  } catch (e) {
    next(e);
  }
});
