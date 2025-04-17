const express = require('express');
const router = express.Router();
const Note = require('../models/Note');
const { body, validationResult, check } = require('express-validator');
const mongoose = require('mongoose');

// --- Input Validation Rules ---
const noteValidationRules = [
    body('title')
        .not().isEmpty().withMessage('Title is required')
        .trim()
        .isLength({ max: 100 }).withMessage('Title cannot exceed 100 characters')
        .escape(), // Escape HTML entities
    body('content')
        .not().isEmpty().withMessage('Content is required')
        .trim()
        .isLength({ max: 5000 }).withMessage('Content cannot exceed 5000 characters')
        .escape(), // Escape HTML entities
];

// Middleware to check for valid MongoDB ObjectId
const validateObjectId = (paramName = 'id') => [
    check(paramName).custom((value) => {
        if (!mongoose.Types.ObjectId.isValid(value)) {
            throw new Error('Invalid ID format');
        }
        return true;
    })
];

// --- Route Handlers ---

// GET / - Display all notes
router.get('/', async (req, res, next) => {
    try {
        const notes = await Note.find().sort({ createdAt: -1 }); // Sort by newest first
        res.render('index', { title: 'All Notes', notes });
    } catch (err) {
        console.error("Error fetching notes:", err);
        next(err); // Pass error to the central error handler
    }
});

// GET /notes/new - Show form to create a new note
router.get('/notes/new', (req, res) => {
    res.render('new', { title: 'New Note', note: {}, errors: [] });
});

// POST /notes - Create a new note
router.post('/notes', noteValidationRules, async (req, res, next) => {
    const errors = validationResult(req);
    const { title, content } = req.body;

    if (!errors.isEmpty()) {
        // If validation fails, re-render the form with errors and entered data
        return res.status(400).render('new', {
            title: 'New Note',
            note: { title, content }, // Pass back the entered data
            errors: errors.array(),
        });
    }

    try {
        const newNote = new Note({ title, content });
        await newNote.save();
        res.redirect('/');
    } catch (err) {
        console.error("Error creating note:", err);
        // Handle potential database errors (like validation errors from Mongoose schema)
        if (err.name === 'ValidationError') {
            const mongooseErrors = Object.values(err.errors).map(e => ({ msg: e.message }));
            return res.status(400).render('new', {
                title: 'New Note',
                note: { title, content },
                errors: mongooseErrors,
            });
        }
        next(err); // Pass other errors to the central handler
    }
});

// GET /notes/:id/edit - Show form to edit a note
router.get('/notes/:id/edit', validateObjectId('id'), async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('error', { title: 'Invalid ID', message: 'Invalid note ID format.' });
    }

    try {
        const note = await Note.findById(req.params.id);
        if (!note) {
            return res.status(404).render('error', { title: 'Not Found', message: 'Note not found.' });
        }
        res.render('edit', { title: 'Edit Note', note, errors: [] });
    } catch (err) {
        console.error("Error fetching note for edit:", err);
        next(err);
    }
});

// PUT /notes/:id - Update a note (using POST override for simplicity in HTML forms)
// We'll use a hidden _method field in the form later
router.post('/notes/:id/update', validateObjectId('id'), noteValidationRules, async (req, res, next) => {
    const validationErrors = validationResult(req);
    const noteId = req.params.id;
    const { title, content } = req.body;

    if (!validationErrors.isEmpty()) {
        return res.status(400).render('edit', {
            title: 'Edit Note',
            note: { _id: noteId, title, content }, // Pass back entered data
            errors: validationErrors.array(),
        });
    }

    try {
        const note = await Note.findByIdAndUpdate(noteId, { title, content }, { new: true, runValidators: true });
        if (!note) {
            return res.status(404).render('error', { title: 'Not Found', message: 'Note not found for update.' });
        }
        res.redirect('/');
    } catch (err) {
        console.error("Error updating note:", err);
        if (err.name === 'ValidationError') {
            const mongooseErrors = Object.values(err.errors).map(e => ({ msg: e.message }));
            return res.status(400).render('edit', {
                title: 'Edit Note',
                note: { _id: noteId, title, content },
                errors: mongooseErrors,
            });
        }
        next(err);
    }
});

// DELETE /notes/:id - Delete a note (using POST override)
router.post('/notes/:id/delete', validateObjectId('id'), async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // This usually won't happen with just ObjectId validation unless the ID is tampered post-load
        return res.status(400).redirect('/'); // Redirect or show error
    }
    try {
        const note = await Note.findByIdAndDelete(req.params.id);
        if (!note) {
            // Note might have been deleted already, treat as success or notify
            console.warn(`Attempted to delete non-existent note: ${req.params.id}`);
            return res.status(404).render('error', { title: 'Not Found', message: 'Note not found for deletion.' });
        }
        res.redirect('/');
    } catch (err) {
        console.error("Error deleting note:", err);
        next(err);
    }
});

module.exports = router; 