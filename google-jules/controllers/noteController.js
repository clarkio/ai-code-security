const { validationResult } = require('express-validator');
const Note = require('../models/note');

// Create a new note
exports.createNote = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { title, content } = req.body;
    const userId = req.user.id; // From authMiddleware

    try {
        const note = await Note.createNote(title, content, userId);
        res.status(201).json(note);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
        // next(err); // Pass to global error handler
    }
};

// Get all notes for the logged-in user
exports.getNotes = async (req, res, next) => {
    const userId = req.user.id; // From authMiddleware

    try {
        const notes = await Note.getNotesByUserId(userId);
        res.json(notes);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
        // next(err);
    }
};

// Get a single note by ID
exports.getNoteById = async (req, res, next) => {
    const noteId = req.params.id;
    const userId = req.user.id; // From authMiddleware

    try {
        const note = await Note.getNoteByIdAndUserId(noteId, userId);
        if (!note) {
            return res.status(404).json({ msg: 'Note not found or access denied' });
        }
        res.json(note);
    } catch (err) {
        console.error(err.message);
        if (err.kind === 'ObjectId') { // Example for MongoDB, adapt for SQLite if needed
            return res.status(404).json({ msg: 'Note not found' });
        }
        res.status(500).send('Server Error');
        // next(err);
    }
};

// Update a note
exports.updateNote = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const noteId = req.params.id;
    const { title, content } = req.body;
    const userId = req.user.id; // From authMiddleware

    try {
        const updatedNote = await Note.updateNoteByIdAndUserId(noteId, title, content, userId);
        if (!updatedNote) {
            return res.status(404).json({ msg: 'Note not found, not owned by user, or no change in data' });
        }
        res.json(updatedNote);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
        // next(err);
    }
};

// Delete a note
exports.deleteNote = async (req, res, next) => {
    const noteId = req.params.id;
    const userId = req.user.id; // From authMiddleware

    try {
        const deletedCount = await Note.deleteNoteByIdAndUserId(noteId, userId);
        if (deletedCount === 0) {
            return res.status(404).json({ msg: 'Note not found or access denied' });
        }
        res.json({ msg: 'Note removed' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
        // next(err);
    }
};
