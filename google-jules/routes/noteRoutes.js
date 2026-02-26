const express = require('express');
const { body } = require('express-validator');
const noteController = require('../controllers/noteController');
const authMiddleware = require('../middleware/authMiddleware');
const csurf = require('csurf');
const router = express.Router();

// CSRF Protection Middleware
// This should be the same instance as configured in app.js if you want to share the secret/config.
// However, for route-specific application, re-initializing might be done,
// but it's better to pass it from app.js or configure it consistently.
// For this task, we'll assume csurf is initialized in app.js and we are just applying it.
// If app.js doesn't pass csrfProtection, this will create a new instance.
const csrfProtection = csurf({ cookie: true });


// Validation middleware for creating and updating notes
const noteValidation = [
    body('title', 'Title is required').not().isEmpty().trim().escape(),
    body('content', 'Content is required').not().isEmpty().trim().escape()
];

// Protect all routes defined below with authMiddleware
router.use(authMiddleware);

// POST /api/notes - Create a new note
router.post('/', csrfProtection, noteValidation, noteController.createNote);

// GET /api/notes - Get all notes for the logged-in user
router.get('/', noteController.getNotes); // CSRF not typically needed for GET

// GET /api/notes/:id - Get a single note by ID
router.get('/:id', noteController.getNoteById); // CSRF not typically needed for GET

// PUT /api/notes/:id - Update a note by ID
router.put('/:id', csrfProtection, noteValidation, noteController.updateNote);

// DELETE /api/notes/:id - Delete a note by ID
router.delete('/:id', csrfProtection, noteController.deleteNote);

module.exports = router;
