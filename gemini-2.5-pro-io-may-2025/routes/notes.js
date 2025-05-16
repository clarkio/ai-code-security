// routes/notes.js
const express = require('express');
const { body, validationResult, param } = require('express-validator');
const db = require('../db');
const { isAuthenticated } = require('../middleware/authMiddleware');
const router = express.Router();

// View all notes for the logged-in user
router.get('/', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM notes WHERE userId = ? ORDER BY updatedAt DESC', [req.session.userId], (err, notes) => {
        if (err) {
            console.error('Error fetching notes:', err.message);
            req.flash('error', 'Could not fetch notes.');
            return res.render('notes', { title: 'My Notes', notes: [], user: req.session.username });
        }
        res.render('notes', { title: 'My Notes', notes: notes, user: req.session.username });
    });
});

// Create new note (form is on the /notes page)
router.post('/', isAuthenticated, [
    body('title')
        .trim()
        .isLength({ min: 1, max: 100 }).withMessage('Title must be between 1 and 100 characters.')
        .escape(),
    body('content')
        .trim()
        .isLength({ min: 1 }).withMessage('Content cannot be empty.')
    // No .escape() for content here IF you want to allow some safe HTML and sanitize it differently.
    // For plain text notes, escaping is fine. If you render it with <%- content %>, then you NEED sanitization.
    // EJS <%= content %> will escape by default, which is safer.
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(e => e.msg).join(', '));
        return res.redirect('/notes'); // Redirect back to notes page, errors shown via flash
    }

    const { title, content } = req.body;
    const userId = req.session.userId;

    db.run('INSERT INTO notes (userId, title, content, updatedAt) VALUES (?, ?, ?, datetime("now"))',
        [userId, title, content], function (err) {
        if (err) {
            console.error('Error creating note:', err.message);
            req.flash('error', 'Failed to create note.');
        } else {
            req.flash('success', 'Note created successfully!');
        }
        res.redirect('/notes');
    });
});

// Edit note page
router.get('/edit/:id', isAuthenticated, [
    param('id').isInt({ gt: 0 }).withMessage('Invalid note ID.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', 'Invalid note ID.');
        return res.redirect('/notes');
    }
    const noteId = req.params.id;
    const userId = req.session.userId;

    db.get('SELECT * FROM notes WHERE id = ? AND userId = ?', [noteId, userId], (err, note) => {
        if (err) {
            console.error('Error fetching note for edit:', err.message);
            req.flash('error', 'Could not fetch note.');
            return res.redirect('/notes');
        }
        if (!note) {
            req.flash('error', 'Note not found or you do not have permission to edit it.');
            return res.status(404).redirect('/notes');
        }
        res.render('edit-note', { title: 'Edit Note', note, user: req.session.username });
    });
});

// Update note
router.post('/update/:id', isAuthenticated, [
    param('id').isInt({ gt: 0 }).withMessage('Invalid note ID.'),
    body('title')
        .trim()
        .isLength({ min: 1, max: 100 }).withMessage('Title must be between 1 and 100 characters.')
        .escape(),
    body('content')
        .trim()
        .isLength({ min: 1 }).withMessage('Content cannot be empty.')
], (req, res) => {
    const errors = validationResult(req);
    const noteId = req.params.id; // Get id for redirect even if validation fails

    if (!errors.isEmpty()) {
        req.flash('error', errors.array().map(e => e.msg).join(', '));
        // Fetch note again to re-render edit page with errors
        return db.get('SELECT * FROM notes WHERE id = ? AND userId = ?', [noteId, req.session.userId], (err, note) => {
            if (err || !note) { // If note fetch fails or note not found, redirect to notes list
                req.flash('error', 'Error loading note for edit or note not found.');
                return res.redirect('/notes');
            }
            res.status(400).render('edit-note', {
                title: 'Edit Note',
                note: { ...note, ...req.body }, // Preserve original note data, override with user input
                errors: errors.array(),
                user: req.session.username
            });
        });
    }

    const { title, content } = req.body;
    const userId = req.session.userId;

    db.run('UPDATE notes SET title = ?, content = ?, updatedAt = datetime("now") WHERE id = ? AND userId = ?',
        [title, content, noteId, userId], function (err) {
        if (err) {
            console.error('Error updating note:', err.message);
            req.flash('error', 'Failed to update note.');
            return res.redirect(`/notes/edit/${noteId}`);
        }
        if (this.changes === 0) {
            req.flash('error', 'Note not found or you do not have permission to update it.');
            return res.status(404).redirect('/notes');
        }
        req.flash('success', 'Note updated successfully!');
        res.redirect('/notes');
    });
});

// Delete note
router.post('/delete/:id', isAuthenticated, [
    param('id').isInt({ gt: 0 }).withMessage('Invalid note ID.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', 'Invalid note ID for deletion.');
        return res.redirect('/notes');
    }

    const noteId = req.params.id;
    const userId = req.session.userId;

    db.run('DELETE FROM notes WHERE id = ? AND userId = ?', [noteId, userId], function (err) {
        if (err) {
            console.error('Error deleting note:', err.message);
            req.flash('error', 'Failed to delete note.');
        } else if (this.changes === 0) {
            req.flash('error', 'Note not found or you do not have permission to delete it.');
        } else {
            req.flash('success', 'Note deleted successfully!');
        }
        res.redirect('/notes');
    });
});

module.exports = router;