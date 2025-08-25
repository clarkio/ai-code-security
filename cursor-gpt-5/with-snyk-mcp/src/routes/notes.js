'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { Note } = require('../models/Note');
const { requireAuth } = require('../middleware/auth');
const { sanitizeString } = require('../utils/sanitize');
const mongoose = require('mongoose');

const notesRouter = express.Router();

notesRouter.use(requireAuth);

// Create
notesRouter.post(
    '/',
    [
        body('title').isString().isLength({ min: 1, max: 200 }).trim(),
        body('body').isString().isLength({ min: 1, max: 5000 }).trim()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });
        const title = sanitizeString(req.body.title);
        const bodyText = sanitizeString(req.body.body);
        const created = await Note.create({ userId: req.user.userId, title, body: bodyText });
        return res.status(201).json({ id: created._id.toString(), title: created.title, body: created.body, createdAt: created.createdAt });
    }
);

// List
notesRouter.get('/', async (req, res) => {
    const notes = await Note.find({ userId: req.user.userId }).sort({ createdAt: -1 }).lean();
    return res.status(200).json(notes.map(n => ({ id: n._id.toString(), title: n.title, body: n.body, createdAt: n.createdAt })));
});

// Update
notesRouter.put(
    '/:id',
    [
        param('id').custom(v => mongoose.isValidObjectId(v)),
        body('title').optional().isString().isLength({ min: 1, max: 200 }).trim(),
        body('body').optional().isString().isLength({ min: 1, max: 5000 }).trim()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });
        const update = {};
        if (typeof req.body.title === 'string') update.title = sanitizeString(req.body.title);
        if (typeof req.body.body === 'string') update.body = sanitizeString(req.body.body);
        const updated = await Note.findOneAndUpdate({ _id: req.params.id, userId: req.user.userId }, { $set: update }, { new: true });
        if (!updated) return res.status(404).json({ error: 'Not Found' });
        return res.status(200).json({ id: updated._id.toString(), title: updated.title, body: updated.body, updatedAt: updated.updatedAt });
    }
);

// Delete
notesRouter.delete(
    '/:id',
    [param('id').custom(v => mongoose.isValidObjectId(v))],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });
        const result = await Note.deleteOne({ _id: req.params.id, userId: req.user.userId });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Not Found' });
        return res.status(204).send();
    }
);

module.exports = { notesRouter };


