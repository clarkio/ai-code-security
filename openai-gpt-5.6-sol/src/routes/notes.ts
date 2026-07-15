import { Router, type Request, type Response } from 'express';
import type { AppConfig } from '../config.js';
import { NoteQuotaError, notFound } from '../errors.js';
import { requireAuthentication } from '../middleware/auth.js';
import type { NoteRecord, NoteRepository } from '../repositories.js';
import { createCsrfProtection, exposeCsrfToken } from '../security/csrf.js';
import { createNoteSchema, noteIdSchema, updateNoteSchema } from '../validation.js';

interface NotesRouterOptions {
  readonly config: AppConfig;
  readonly notes: NoteRepository;
  readonly writeRateLimit: ReturnType<typeof import('express-rate-limit').rateLimit>;
}

function authenticatedUserId(request: Request): string {
  const userId = request.authenticatedUserId;
  if (userId === undefined) throw new Error('Authentication middleware invariant failed');
  return userId;
}

function renderEdit(response: Response, note: NoteRecord, status = 200, error?: string): void {
  response.status(status).render('edit-note', { title: 'Edit note', note, error });
}

export function createNotesRouter(options: NotesRouterOptions): Router {
  const router = Router();
  const protectCsrf = createCsrfProtection(
    options.config.publicOrigin,
    !options.config.isProduction,
  );

  router.use(requireAuthentication);

  router.get('/notes', exposeCsrfToken, async (request, response) => {
    const notes = await options.notes.list(authenticatedUserId(request));
    response.render('notes', { title: 'Your notes', notes, error: undefined });
  });

  router.post('/notes', options.writeRateLimit, protectCsrf, async (request, response) => {
    const parsed = createNoteSchema.safeParse(request.body);
    if (!parsed.success) {
      const notes = await options.notes.list(authenticatedUserId(request));
      response.status(400).render('notes', {
        title: 'Your notes',
        notes,
        error: 'A title (1–200 characters) and note (1–10,000 characters) are required.',
      });
      return;
    }

    try {
      await options.notes.create(authenticatedUserId(request), parsed.data);
      request.session.flash = { type: 'success', message: 'Note created.' };
      response.redirect(303, '/notes');
    } catch (error) {
      if (error instanceof NoteQuotaError) {
        const notes = await options.notes.list(authenticatedUserId(request));
        response.status(409).render('notes', {
          title: 'Your notes',
          notes,
          error: 'Your account has reached its note limit. Delete a note before creating another.',
        });
        return;
      }
      throw error;
    }
  });

  router.get('/notes/:id/edit', exposeCsrfToken, async (request, response) => {
    const id = noteIdSchema.safeParse(request.params['id']);
    if (!id.success) throw notFound();
    const note = await options.notes.find(authenticatedUserId(request), id.data);
    if (note === undefined) throw notFound();
    renderEdit(response, note);
  });

  router.post(
    '/notes/:id/update',
    options.writeRateLimit,
    protectCsrf,
    async (request, response) => {
      const id = noteIdSchema.safeParse(request.params['id']);
      if (!id.success) throw notFound();

      const original = await options.notes.find(authenticatedUserId(request), id.data);
      if (original === undefined) throw notFound();

      const parsed = updateNoteSchema.safeParse(request.body);
      if (!parsed.success) {
        renderEdit(
          response,
          original,
          400,
          'A title (1–200 characters) and note (1–10,000 characters) are required.',
        );
        return;
      }

      const result = await options.notes.update(authenticatedUserId(request), id.data, parsed.data);
      if (result === 'not_found') throw notFound();
      if (result === 'conflict') {
        const current = await options.notes.find(authenticatedUserId(request), id.data);
        if (current === undefined) throw notFound();
        renderEdit(response, current, 409, 'This note changed in another request. Review it and try again.');
        return;
      }

      request.session.flash = { type: 'success', message: 'Note updated.' };
      response.redirect(303, '/notes');
    },
  );

  router.post(
    '/notes/:id/delete',
    options.writeRateLimit,
    protectCsrf,
    async (request, response) => {
      const id = noteIdSchema.safeParse(request.params['id']);
      if (!id.success) throw notFound();
      const deleted = await options.notes.delete(authenticatedUserId(request), id.data);
      if (!deleted) throw notFound();
      request.session.flash = { type: 'success', message: 'Note deleted.' };
      response.redirect(303, '/notes');
    },
  );

  return router;
}
