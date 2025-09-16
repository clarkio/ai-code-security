const express = require('express');
const notesService = require('../services/notesService');
const authService = require('../services/authService');
const { validateNoteCreation, validateNoteUpdate, validatePagination } = require('../middleware/validation');
const logger = require('../utils/logger');

const router = express.Router();

// Authentication middleware for all note routes
const authenticateUser = authService.createAuthMiddleware();

/**
 * POST /api/notes - Create a new note
 * Requires authentication and validates input
 */
router.post('/', authenticateUser, validateNoteCreation, async (req, res) => {
  try {
    const { title, content } = req.body;
    const userId = req.userId;

    // Create note with user ownership
    const note = await notesService.createNote(userId, { title, content });

    res.status(201).json({
      success: true,
      message: 'Note created successfully',
      data: note
    });

  } catch (error) {
    logger.error('Note creation endpoint error', {
      error: error.message,
      userId: req.userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle validation errors
    if (error.message.includes('required') || 
        error.message.includes('cannot exceed') ||
        error.message.includes('harmful content') ||
        error.message.includes('Maximum number')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to create note. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * GET /api/notes - Get user's notes with pagination
 * Requires authentication and validates pagination parameters
 */
router.get('/', authenticateUser, validatePagination, async (req, res) => {
  try {
    const userId = req.userId;
    const { page, limit } = req.query;
    const includeDeleted = req.query.includeDeleted === 'true';

    // Get notes with pagination
    const result = await notesService.getNotes(userId, {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      includeDeleted
    });

    res.json({
      success: true,
      data: result.notes,
      pagination: result.pagination
    });

  } catch (error) {
    logger.error('Notes retrieval endpoint error', {
      error: error.message,
      userId: req.userId,
      query: req.query,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle validation errors
    if (error.message.includes('must be') || error.message.includes('invalid')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve notes. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * GET /api/notes/search - Search user's notes
 * Requires authentication and validates search parameters
 */
router.get('/search', authenticateUser, validatePagination, async (req, res) => {
  try {
    const userId = req.userId;
    const { q: searchTerm, page, limit } = req.query;

    if (!searchTerm) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Search term (q) is required',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Search notes
    const result = await notesService.searchNotes(userId, searchTerm, {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10)
    });

    res.json({
      success: true,
      data: result.notes,
      searchTerm: result.searchTerm,
      pagination: result.pagination
    });

  } catch (error) {
    logger.error('Notes search endpoint error', {
      error: error.message,
      userId: req.userId,
      searchTerm: req.query.q ? '[REDACTED]' : undefined,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle validation errors
    if (error.message.includes('required') || 
        error.message.includes('must be') ||
        error.message.includes('too long') ||
        error.message.includes('too short')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to search notes. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * GET /api/notes/stats - Get user's note statistics
 * Requires authentication
 */
router.get('/stats', authenticateUser, async (req, res) => {
  try {
    const userId = req.userId;

    // Get note statistics
    const stats = await notesService.getNoteStats(userId);

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    logger.error('Notes stats endpoint error', {
      error: error.message,
      userId: req.userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve note statistics. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * GET /api/notes/:id - Get a specific note by ID
 * Requires authentication and ownership verification
 */
router.get('/:id', authenticateUser, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;

    // Get note with ownership verification
    const note = await notesService.getNote(userId, noteId);

    res.json({
      success: true,
      data: note
    });

  } catch (error) {
    logger.error('Note retrieval endpoint error', {
      error: error.message,
      userId: req.userId,
      noteId: req.params.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle not found errors
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Note not found',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Handle validation errors
    if (error.message.includes('Invalid') || error.message.includes('format')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve note. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * PUT /api/notes/:id - Update a specific note
 * Requires authentication, ownership verification, and validates input
 */
router.put('/:id', authenticateUser, validateNoteUpdate, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;
    const { title, content } = req.body;

    // Update note with ownership verification
    const updatedNote = await notesService.updateNote(userId, noteId, { title, content });

    res.json({
      success: true,
      message: 'Note updated successfully',
      data: updatedNote
    });

  } catch (error) {
    logger.error('Note update endpoint error', {
      error: error.message,
      userId: req.userId,
      noteId: req.params.id,
      updateFields: Object.keys(req.body),
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle not found errors
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Note not found',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Handle validation errors
    if (error.message.includes('required') || 
        error.message.includes('cannot exceed') ||
        error.message.includes('harmful content') ||
        error.message.includes('Invalid') ||
        error.message.includes('must be provided')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to update note. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * DELETE /api/notes/:id - Delete a specific note (soft delete)
 * Requires authentication and ownership verification
 */
router.delete('/:id', authenticateUser, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;

    // Delete note with ownership verification
    const result = await notesService.deleteNote(userId, noteId);

    res.json({
      success: true,
      message: result.message,
      noteId: result.noteId
    });

  } catch (error) {
    logger.error('Note deletion endpoint error', {
      error: error.message,
      userId: req.userId,
      noteId: req.params.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle not found errors
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Note not found',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Handle validation errors
    if (error.message.includes('Invalid') || error.message.includes('format')) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }

    // Generic error response
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to delete note. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

module.exports = router;