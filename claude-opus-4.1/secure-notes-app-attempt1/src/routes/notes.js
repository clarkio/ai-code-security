const express = require('express');
const router = express.Router();
const notesController = require('../controllers/notesController');
const { validateNote } = require('../validators/noteValidator');
const authenticate = require('../middleware/auth');

// Create a new note
router.post('/', authenticate, validateNote, notesController.createNote);

// Update an existing note
router.put('/:id', authenticate, validateNote, notesController.updateNote);

// Delete a note
router.delete('/:id', authenticate, notesController.deleteNote);

// Get all notes
router.get('/', authenticate, notesController.getAllNotes);

// Get a single note by ID
router.get('/:id', authenticate, notesController.getNoteById);

module.exports = router;