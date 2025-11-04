const express = require('express');
const { body, validationResult, param } = require('express-validator');
const { pool } = require('../config/database');

const router = express.Router();

// Input validation rules
const noteValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Title must be between 1 and 255 characters')
    .escape(), // XSS prevention
  body('content')
    .trim()
    .isLength({ min: 1, max: 10000 })
    .withMessage('Content must be between 1 and 10000 characters')
    .escape(), // XSS prevention
];

const idValidation = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('Invalid note ID'),
];

// Get all notes for authenticated user
router.get('/', async (req, res, next) => {
  try {
    // Parameterized query prevents SQL injection
    const result = await pool.query(
      'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = $1 ORDER BY updated_at DESC',
      [req.user.id]
    );

    res.json({ notes: result.rows });
  } catch (error) {
    next(error);
  }
});

// Get single note by ID
router.get('/:id', idValidation, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;

    // Verify note belongs to user (parameterized query)
    const result = await pool.query(
      'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({ note: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Create new note
router.post('/', noteValidation, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, content } = req.body;

    // Insert note (parameterized query prevents SQL injection)
    const result = await pool.query(
      'INSERT INTO notes (user_id, title, content) VALUES ($1, $2, $3) RETURNING id, title, content, created_at, updated_at',
      [req.user.id, title, content]
    );

    res.status(201).json({ note: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Update existing note
router.put('/:id', idValidation.concat(noteValidation), async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { title, content } = req.body;

    // Update note (parameterized query prevents SQL injection)
    // Verify note belongs to user
    const result = await pool.query(
      'UPDATE notes SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND user_id = $4 RETURNING id, title, content, created_at, updated_at',
      [title, content, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({ note: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Delete note
router.delete('/:id', idValidation, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;

    // Delete note (parameterized query prevents SQL injection)
    // Verify note belongs to user
    const result = await pool.query(
      'DELETE FROM notes WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({ message: 'Note deleted successfully' });
  } catch (error) {
    next(error);
  }
});

module.exports = router;

