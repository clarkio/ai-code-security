const express = require('express');
const { Op } = require('sequelize');
const { Note, User } = require('../models');
const { verifyToken, optionalAuth, checkOwnership } = require('../middleware/auth');
const { generalLimiter, strictLimiter } = require('../middleware/security');
const { noteValidation } = require('../middleware/validation');

const router = express.Router();

// Get note by ID for ownership check
const getNoteById = async (req) => {
  return await Note.findByPk(req.params.id);
};

// Create a new note
router.post('/',
  verifyToken,
  generalLimiter,
  noteValidation.create,
  async (req, res) => {
    try {
      const { title, content, is_public, tags } = req.body;

      const note = await Note.create({
        title,
        content,
        is_public: is_public || false,
        tags: tags || [],
        user_id: req.userId
      });

      res.status(201).json({
        message: 'Note created successfully',
        note
      });

    } catch (error) {
      console.error('Note creation error:', error);
      res.status(500).json({
        error: 'Failed to create note',
        code: 'NOTE_CREATE_ERROR'
      });
    }
  }
);

// Get all notes for authenticated user
router.get('/my',
  verifyToken,
  noteValidation.list,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, search, tag } = req.query;
      const offset = (page - 1) * limit;

      // Build where clause
      const where = { user_id: req.userId };
      
      if (search) {
        where[Op.or] = [
          { title: { [Op.like]: `%${search}%` } },
          { content: { [Op.like]: `%${search}%` } }
        ];
      }

      // Find notes with pagination
      const { count, rows: notes } = await Note.findAndCountAll({
        where,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']],
        include: [{
          model: User,
          as: 'author',
          attributes: ['id', 'username']
        }]
      });

      // Filter by tag if provided
      let filteredNotes = notes;
      if (tag) {
        filteredNotes = notes.filter(note => 
          note.tags && note.tags.includes(tag)
        );
      }

      res.json({
        notes: filteredNotes,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(count / limit)
        }
      });

    } catch (error) {
      console.error('Notes fetch error:', error);
      res.status(500).json({
        error: 'Failed to fetch notes',
        code: 'NOTES_FETCH_ERROR'
      });
    }
  }
);

// Get public notes
router.get('/public',
  optionalAuth,
  noteValidation.list,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, search, tag } = req.query;
      const offset = (page - 1) * limit;

      // Build where clause
      const where = { is_public: true };
      
      if (search) {
        where[Op.or] = [
          { title: { [Op.like]: `%${search}%` } },
          { content: { [Op.like]: `%${search}%` } }
        ];
      }

      // Find public notes
      const { count, rows: notes } = await Note.findAndCountAll({
        where,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']],
        include: [{
          model: User,
          as: 'author',
          attributes: ['id', 'username']
        }]
      });

      // Filter by tag if provided
      let filteredNotes = notes;
      if (tag) {
        filteredNotes = notes.filter(note => 
          note.tags && note.tags.includes(tag)
        );
      }

      res.json({
        notes: filteredNotes,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(count / limit)
        }
      });

    } catch (error) {
      console.error('Public notes fetch error:', error);
      res.status(500).json({
        error: 'Failed to fetch public notes',
        code: 'PUBLIC_NOTES_FETCH_ERROR'
      });
    }
  }
);

// Get note by ID
router.get('/:id',
  optionalAuth,
  noteValidation.getById,
  async (req, res) => {
    try {
      const note = await Note.findByPk(req.params.id, {
        include: [{
          model: User,
          as: 'author',
          attributes: ['id', 'username']
        }]
      });

      if (!note) {
        return res.status(404).json({
          error: 'Note not found',
          code: 'NOTE_NOT_FOUND'
        });
      }

      // Check access permissions
      if (!note.is_public && (!req.userId || note.user_id !== req.userId)) {
        return res.status(403).json({
          error: 'Access denied',
          code: 'FORBIDDEN'
        });
      }

      // Increment view count
      await note.increment('view_count');

      res.json({ note });

    } catch (error) {
      console.error('Note fetch error:', error);
      res.status(500).json({
        error: 'Failed to fetch note',
        code: 'NOTE_FETCH_ERROR'
      });
    }
  }
);

// Update note
router.put('/:id',
  verifyToken,
  noteValidation.update,
  checkOwnership(getNoteById),
  async (req, res) => {
    try {
      const { title, content, is_public, tags } = req.body;
      const note = req.resource;

      // Update fields if provided
      if (title !== undefined) note.title = title;
      if (content !== undefined) note.content = content;
      if (is_public !== undefined) note.is_public = is_public;
      if (tags !== undefined) note.tags = tags;
      
      note.last_modified_by = req.userId;

      await note.save();

      res.json({
        message: 'Note updated successfully',
        note
      });

    } catch (error) {
      console.error('Note update error:', error);
      res.status(500).json({
        error: 'Failed to update note',
        code: 'NOTE_UPDATE_ERROR'
      });
    }
  }
);

// Delete note
router.delete('/:id',
  verifyToken,
  strictLimiter,
  noteValidation.getById,
  checkOwnership(getNoteById),
  async (req, res) => {
    try {
      const note = req.resource;
      
      // Soft delete (paranoid mode is enabled)
      await note.destroy();

      res.json({
        message: 'Note deleted successfully'
      });

    } catch (error) {
      console.error('Note deletion error:', error);
      res.status(500).json({
        error: 'Failed to delete note',
        code: 'NOTE_DELETE_ERROR'
      });
    }
  }
);

// Get all unique tags for the user
router.get('/tags/all',
  verifyToken,
  async (req, res) => {
    try {
      const notes = await Note.findAll({
        where: { user_id: req.userId },
        attributes: ['tags']
      });

      // Extract unique tags
      const allTags = new Set();
      notes.forEach(note => {
        if (note.tags && Array.isArray(note.tags)) {
          note.tags.forEach(tag => allTags.add(tag));
        }
      });

      res.json({
        tags: Array.from(allTags).sort()
      });

    } catch (error) {
      console.error('Tags fetch error:', error);
      res.status(500).json({
        error: 'Failed to fetch tags',
        code: 'TAGS_FETCH_ERROR'
      });
    }
  }
);

module.exports = router;