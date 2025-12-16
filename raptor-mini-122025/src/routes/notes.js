const express = require('express');
const Joi = require('joi');

const noteSchema = Joi.object({
  title: Joi.string().max(255).required(),
  body: Joi.string().max(5000).allow('').required()
});

module.exports = (knex) => {
  const router = express.Router();

  // auth middleware
  router.use((req, res, next) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    next();
  });

  router.get('/', async (req, res, next) => {
    try {
      const notes = await knex('notes').where({ owner_id: req.session.userId }).select('id', 'title', 'body', 'created_at', 'updated_at');
      res.json(notes);
    } catch (err) { next(err); }
  });

  router.post('/', async (req, res, next) => {
    try {
      const { error, value } = noteSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.message });

      const note = {
        id: require('uuid').v4(),
        owner_id: req.session.userId,
        title: value.title,
        body: value.body,
        created_at: new Date(),
        updated_at: new Date()
      };
      await knex('notes').insert(note);
      res.status(201).json({ id: note.id });
    } catch (err) { next(err); }
  });

  router.put('/:id', async (req, res, next) => {
    try {
      const { error, value } = noteSchema.validate(req.body);
      if (error) return res.status(400).json({ error: error.message });

      const note = await knex('notes').where({ id: req.params.id }).first();
      if (!note) return res.status(404).json({ error: 'Not found' });
      if (note.owner_id !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });

      await knex('notes').where({ id: req.params.id }).update({ title: value.title, body: value.body, updated_at: new Date() });
      res.json({ ok: true });
    } catch (err) { next(err); }
  });

  router.delete('/:id', async (req, res, next) => {
    try {
      const note = await knex('notes').where({ id: req.params.id }).first();
      if (!note) return res.status(404).json({ error: 'Not found' });
      if (note.owner_id !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });

      await knex('notes').where({ id: req.params.id }).del();
      res.json({ ok: true });
    } catch (err) { next(err); }
  });

  return router;
};