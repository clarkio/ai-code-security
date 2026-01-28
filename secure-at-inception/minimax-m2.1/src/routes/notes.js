/**
 * Notes Routes
 * CRUD operations for notes with security controls
 */
const express = require('express');
const router = express.Router();
const NotesModel = require('../models/note');
const { authenticate } = require('../middleware/auth');
const { asyncHandler, ApiError } = require('../middleware/errorHandler');
const InputValidator = require('../utils/validator');
const { csrfProtection, setCsrfToken } = require('../middleware/csrf');

// Apply CSRF token to all notes routes
router.use(setCsrfToken);

/**
 * GET /notes
 * Get all notes for authenticated user
 */
router.get('/', authenticate, asyncHandler(async (req, res) => {
  const notes = NotesModel.getAllByUserId(req.userId);
  
  res.json({
    notes: notes.map(note => ({
      id: note.id,
      title: note.title,
      content: note.content,
      createdAt: note.created_at,
      updatedAt: note.updated_at
    }))
  });
}));

/**
 * GET /notes/:id
 * Get a single note by ID
 */
router.get('/:id', authenticate, asyncHandler(async (req, res) => {
  const { id } = req.params;
  
  const note = NotesModel.getById(id, req.userId);
  
  if (!note) {
    throw ApiError.notFound('Note not found or access denied');
  }

  res.json({
    note: {
      id: note.id,
      title: note.title,
      content: note.content,
      createdAt: note.created_at,
      updatedAt: note.updated_at
    }
  });
}));

/**
 * POST /notes
 * Create a new note
 */
router.post('/', authenticate, csrfProtection, asyncHandler(async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content) {
    throw ApiError.badRequest('Title and content are required');
  }

  const note = NotesModel.create(req.userId, title, content);

  res.status(201).json({
    message: 'Note created successfully',
    note: {
      id: note.id,
      title: note.title,
      content: note.content,
      createdAt: note.created_at,
      updatedAt: note.updated_at
    }
  });
}));

/**
 * PUT /notes/:id
 * Update an existing note
 */
router.put('/:id', authenticate, csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  if (!title && !content) {
    throw ApiError.badRequest('At least title or content is required');
  }

  const updates = {};
  if (title !== undefined) updates.title = title;
  if (content !== undefined) updates.content = content;

  const note = NotesModel.update(id, req.userId, updates);

  if (!note) {
    throw ApiError.notFound('Note not found or access denied');
  }

  res.json({
    message: 'Note updated successfully',
    note: {
      id: note.id,
      title: note.title,
      content: note.content,
      createdAt: note.created_at,
      updatedAt: note.updated_at
    }
  });
}));

/**
 * PATCH /notes/:id
 * Partial update of a note
 */
router.patch('/:id', authenticate, csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  if (!title && !content) {
    throw ApiError.badRequest('At least title or content is required');
  }

  const updates = {};
  if (title !== undefined) updates.title = title;
  if (content !== undefined) updates.content = content;

  const note = NotesModel.update(id, req.userId, updates);

  if (!note) {
    throw ApiError.notFound('Note not found or access denied');
  }

  res.json({
    message: 'Note updated successfully',
    note: {
      id: note.id,
      title: note.title,
      content: note.content,
      createdAt: note.created_at,
      updatedAt: note.updated_at
    }
  });
}));

/**
 * DELETE /notes/:id
 * Delete a note
 */
router.delete('/:id', authenticate, csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  
  const deleted = NotesModel.delete(id, req.userId);
  
  if (!deleted) {
    throw ApiError.notFound('Note not found or access denied');
  }

  res.json({
    message: 'Note deleted successfully'
  });
}));

module.exports = router;
