import express from 'express';
import { buildRateLimiter } from '../security.js';
import { noteCreateSchema, noteUpdateSchema, noteIdSchema } from '../schema.js';
import { listNotesByUser, createNote, getNoteByIdAndUser, updateNote, deleteNote } from '../db.js';

const router = express.Router();
const mutateLimiter = buildRateLimiter({ windowMs: 60 * 1000, max: 60 });

router.get('/', (req, res) => {
    const notes = listNotesByUser(req.session.userId);
    res.render('notes/index', { notes });
});

router.get('/new', (req, res) => {
    res.render('notes/new');
});

router.post('/', mutateLimiter, (req, res) => {
    try {
        const { title, body } = noteCreateSchema.parse({ title: String(req.body.title || ''), body: String(req.body.body || '') });
        const id = createNote({ userId: req.session.userId, title, body });
        res.redirect(`/notes/${id}`);
    } catch (e) {
        res.status(400).render('notes/new', { error: 'Invalid input' });
    }
});

router.get('/:id', (req, res) => {
    try {
        const id = noteIdSchema.parse(req.params.id);
        const note = getNoteByIdAndUser(id, req.session.userId);
        if (!note) return res.status(404).render('error', { message: 'Note not found' });
        res.render('notes/show', { note });
    } catch (e) {
        res.status(400).render('error', { message: 'Invalid note id' });
    }
});

router.get('/:id/edit', (req, res) => {
    try {
        const id = noteIdSchema.parse(req.params.id);
        const note = getNoteByIdAndUser(id, req.session.userId);
        if (!note) return res.status(404).render('error', { message: 'Note not found' });
        res.render('notes/edit', { note });
    } catch (e) {
        res.status(400).render('error', { message: 'Invalid note id' });
    }
});

router.post('/:id', mutateLimiter, (req, res) => {
    try {
        const id = noteIdSchema.parse(req.params.id);
        const { title, body } = noteUpdateSchema.parse({ title: String(req.body.title || ''), body: String(req.body.body || '') });
        const ok = updateNote({ id, userId: req.session.userId, title, body });
        if (!ok) return res.status(404).render('error', { message: 'Note not found' });
        res.redirect(`/notes/${id}`);
    } catch (e) {
        res.status(400).render('error', { message: 'Invalid input' });
    }
});

router.get('/:id/delete', (req, res) => {
    try {
        const id = noteIdSchema.parse(req.params.id);
        const note = getNoteByIdAndUser(id, req.session.userId);
        if (!note) return res.status(404).render('error', { message: 'Note not found' });
        res.render('confirm-delete', { title: note.title, action: `/notes/${id}/delete`, cancelHref: `/notes/${id}` });
    } catch (e) {
        res.status(400).render('error', { message: 'Invalid note id' });
    }
});

router.post('/:id/delete', mutateLimiter, (req, res) => {
    try {
        const id = noteIdSchema.parse(req.params.id);
        const ok = deleteNote({ id, userId: req.session.userId });
        if (!ok) return res.status(404).render('error', { message: 'Note not found' });
        res.redirect('/notes');
    } catch (e) {
        res.status(400).render('error', { message: 'Invalid note id' });
    }
});

export default router;


