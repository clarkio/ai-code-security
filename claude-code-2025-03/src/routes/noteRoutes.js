const express = require('express');
const router = express.Router();
const noteController = require('../controllers/noteController');
const { isAuthenticated, isResourceOwner } = require('../middleware/auth');
const { noteValidationRules, validate } = require('../middleware/validation');
const { apiLimiter, csrfProtection } = require('../middleware/security');

// Apply authentication to all note routes
router.use(isAuthenticated);

// Apply rate limiting to all note routes
router.use(apiLimiter);

// Apply CSRF protection to all mutating routes
router.post('*', csrfProtection);
router.put('*', csrfProtection);
router.patch('*', csrfProtection);
router.delete('*', csrfProtection);

// Get all notes for current user
router.get('/', noteController.getNotes);

// Get a single note by ID with ownership check
router.get('/:id', noteController.getNoteById, isResourceOwner);

// Create a new note
router.post(
  '/',
  noteValidationRules,
  validate,
  noteController.createNote
);

// Update a note
router.put(
  '/:id',
  noteValidationRules,
  validate,
  noteController.updateNote
);

// Delete a note
router.delete('/:id', noteController.deleteNote);

module.exports = router;