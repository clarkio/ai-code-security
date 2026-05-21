import { Router } from 'express';
import {
  createNote,
  deleteNote,
  getNoteForUser,
  listNotesForUser,
  updateNote,
} from '../db/database.js';
import { requireAuth } from '../middleware/auth.js';
import { writeLimiter } from '../middleware/rateLimit.js';
import { validateBody, validateParams } from '../middleware/validate.js';
import { noteIdParamSchema, noteSchema } from '../validation/schemas.js';

const router = Router();

router.use(requireAuth);

router.get('/', (req, res) => {
  const notes = listNotesForUser(req.session.userId);
  res.render('notes/index', { title: 'My notes', notes });
});

router.get('/new', (req, res) => {
  res.render('notes/form', {
    title: 'New note',
    note: null,
    formAction: '/notes',
    submitLabel: 'Create note',
  });
});

router.post(
  '/',
  writeLimiter,
  validateBody(noteSchema),
  (req, res) => {
    const { title, body } = req.validated;
    createNote(req.session.userId, title, body ?? '');
    req.session.flash = { type: 'success', message: 'Note created.' };
    res.redirect('/notes');
  }
);

router.get(
  '/:id/edit',
  validateParams(noteIdParamSchema),
  (req, res) => {
    const note = getNoteForUser(req.validatedParams, req.session.userId);
    if (!note) {
      return res.status(404).render('error', {
        title: 'Not found',
        message: 'Note not found.',
        statusCode: 404,
      });
    }
    res.render('notes/form', {
      title: 'Edit note',
      note,
      formAction: `/notes/${note.id}`,
      submitLabel: 'Save changes',
    });
  }
);

router.post(
  '/:id',
  writeLimiter,
  validateParams(noteIdParamSchema),
  validateBody(noteSchema),
  (req, res) => {
    const noteId = req.validatedParams;
    const { title, body } = req.validated;
    const updated = updateNote(noteId, req.session.userId, title, body ?? '');
    if (!updated) {
      return res.status(404).render('error', {
        title: 'Not found',
        message: 'Note not found.',
        statusCode: 404,
      });
    }
    req.session.flash = { type: 'success', message: 'Note updated.' };
    res.redirect('/notes');
  }
);

router.post(
  '/:id/delete',
  writeLimiter,
  validateParams(noteIdParamSchema),
  (req, res) => {
    const noteId = req.validatedParams;
    const removed = deleteNote(noteId, req.session.userId);
    if (!removed) {
      return res.status(404).render('error', {
        title: 'Not found',
        message: 'Note not found.',
        statusCode: 404,
      });
    }
    req.session.flash = { type: 'success', message: 'Note deleted.' };
    res.redirect('/notes');
  }
);

export default router;
