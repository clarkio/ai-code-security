const express = require('express');
const noteController = require('../controllers/noteController');
const authController = require('../controllers/authController');
const { body } = require('express-validator');

const router = express.Router();

// Protect all routes after this middleware
router.use(authController.protect);

// Input validation middleware
const validateNote = [
  body('title')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be between 1 and 100 characters'),
  body('content')
    .optional()
    .trim()
    .isLength({ min: 1, max: 10000 })
    .withMessage('Content must be between 1 and 10000 characters'),
  body('isPinned')
    .optional()
    .isBoolean()
    .withMessage('isPinned must be a boolean'),
  body('tags')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Maximum 10 tags allowed'),
  body('tags.*')
    .isString()
    .trim()
    .isLength({ min: 1, max: 20 })
    .withMessage('Each tag must be between 1 and 20 characters'),
  body('color')
    .optional()
    .matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/)
    .withMessage('Color must be a valid hex color code'),
  body('isArchived')
    .optional()
    .isBoolean()
    .withMessage('isArchived must be a boolean'),
];

// Routes
router
  .route('/')
  .get(noteController.getAllNotes)
  .post(validateNote, noteController.createNote);

// Search endpoint
router.get('/search', noteController.searchNotes);

// Stats endpoint
router.get('/stats', noteController.getNoteStats);

// Routes for a specific note
router
  .route('/:id')
  .get(noteController.getNote)
  .patch(validateNote, noteController.updateNote)
  .delete(noteController.deleteNote);

module.exports = router;
