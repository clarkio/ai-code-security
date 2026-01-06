import { Router } from 'express';
import createError from 'http-errors';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { requireUser } from '../auth/session';

const router = Router();

const noteSchema = z.object({
  title: z.string().trim().min(1).max(100),
  content: z.string().trim().max(5000).default(''),
});

router.use(requireUser);

router.get('/notes', async (req, res, next) => {
  try {
    const userId = req.session.user!.id;
    const notes = await prisma.note.findMany({
      where: { userId },
      orderBy: { updatedAt: 'desc' },
    });
    res.render('notes_list', { title: 'Your notes', notes, error: null });
  } catch (err) {
    next(err);
  }
});

router.get('/notes/new', (req, res) => {
  res.render('note_form', {
    title: 'New note',
    heading: 'New note',
    action: '/notes',
    submitLabel: 'Create',
    note: null,
    error: null,
  });
});

router.post('/notes', async (req, res, next) => {
  try {
    const userId = req.session.user!.id;
    const parsed = noteSchema.safeParse({ title: req.body.title, content: req.body.content ?? '' });
    if (!parsed.success) {
      return res.status(400).render('note_form', {
        title: 'New note',
        heading: 'New note',
        action: '/notes',
        submitLabel: 'Create',
        note: { title: req.body.title ?? '', content: req.body.content ?? '' },
        error: 'Invalid note input.',
      });
    }

    await prisma.note.create({
      data: { userId, title: parsed.data.title, content: parsed.data.content },
    });

    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

router.get('/notes/:id/edit', async (req, res, next) => {
  try {
    const userId = req.session.user!.id;
    const id = z.string().min(1).parse(req.params.id);

    const note = await prisma.note.findFirst({ where: { id, userId } });
    if (!note) throw createError(404);

    return res.render('note_form', {
      title: 'Edit note',
      heading: 'Edit note',
      action: `/notes/${note.id}`,
      submitLabel: 'Save',
      note,
      error: null,
    });
  } catch (err) {
    return next(err);
  }
});

router.post('/notes/:id', async (req, res, next) => {
  try {
    const userId = req.session.user!.id;
    const id = z.string().min(1).parse(req.params.id);

    const parsed = noteSchema.safeParse({ title: req.body.title, content: req.body.content ?? '' });
    if (!parsed.success) {
      return res.status(400).render('note_form', {
        title: 'Edit note',
        heading: 'Edit note',
        action: `/notes/${id}`,
        submitLabel: 'Save',
        note: { id, title: req.body.title ?? '', content: req.body.content ?? '' },
        error: 'Invalid note input.',
      });
    }

    const updated = await prisma.note.updateMany({
      where: { id, userId },
      data: { title: parsed.data.title, content: parsed.data.content },
    });

    if (updated.count !== 1) throw createError(404);

    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

router.post('/notes/:id/delete', async (req, res, next) => {
  try {
    const userId = req.session.user!.id;
    const id = z.string().min(1).parse(req.params.id);

    const deleted = await prisma.note.deleteMany({ where: { id, userId } });
    if (deleted.count !== 1) throw createError(404);

    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

export default router;
