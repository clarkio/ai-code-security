const express = require('express');
const router = express.Router();
const Note = require('../models/Note');
const { validateNote, validateNoteUpdate, validateNoteId } = require('../middleware/validation');
const { sanitizeBody, sanitizeQuery, sanitizeParams } = require('../middleware/sanitization');
const logger = require('../utils/logger');

const noteModel = new Note();

// Apply sanitization middleware
router.use(sanitizeQuery);
router.use(sanitizeParams);

// GET /api/notes - Get all notes
router.get('/', (req, res) => {
  try {
    const { tag, search } = req.query;
    let notes;

    if (tag) {
      notes = noteModel.getByTag(tag);
    } else if (search) {
      notes = noteModel.search(search);
    } else {
      notes = noteModel.getAll();
    }

    res.json({
      success: true,
      data: notes,
      count: notes.length
    });
  } catch (error) {
    logger.error('Error fetching notes:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch notes'
    });
  }
});

// GET /api/notes/tags - Get all unique tags
router.get('/tags', (req, res) => {
  try {
    const tags = noteModel.getAllTags();
    res.json({
      success: true,
      data: tags,
      count: tags.length
    });
  } catch (error) {
    logger.error('Error fetching tags:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch tags'
    });
  }
});

// GET /api/notes/:id - Get a specific note
router.get('/:id', validateNoteId, (req, res) => {
  try {
    const note = noteModel.getById(req.params.id);
    
    if (!note) {
      return res.status(404).json({
        success: false,
        error: 'Note not found'
      });
    }

    res.json({
      success: true,
      data: note
    });
  } catch (error) {
    logger.error('Error fetching note:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch note'
    });
  }
});

// POST /api/notes - Create a new note
router.post('/', sanitizeBody, validateNote, (req, res) => {
  try {
    const note = noteModel.create(req.body);
    
    res.status(201).json({
      success: true,
      data: note,
      message: 'Note created successfully'
    });
  } catch (error) {
    logger.error('Error creating note:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create note'
    });
  }
});

// PUT /api/notes/:id - Update a note
router.put('/:id', sanitizeBody, validateNoteId, validateNoteUpdate, (req, res) => {
  try {
    const note = noteModel.update(req.params.id, req.body);
    
    if (!note) {
      return res.status(404).json({
        success: false,
        error: 'Note not found'
      });
    }

    res.json({
      success: true,
      data: note,
      message: 'Note updated successfully'
    });
  } catch (error) {
    logger.error('Error updating note:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update note'
    });
  }
});

// DELETE /api/notes/:id - Delete a note
router.delete('/:id', validateNoteId, (req, res) => {
  try {
    const deleted = noteModel.delete(req.params.id);
    
    if (!deleted) {
      return res.status(404).json({
        success: false,
        error: 'Note not found'
      });
    }

    res.json({
      success: true,
      message: 'Note deleted successfully'
    });
  } catch (error) {
    logger.error('Error deleting note:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete note'
    });
  }
});

module.exports = router;
