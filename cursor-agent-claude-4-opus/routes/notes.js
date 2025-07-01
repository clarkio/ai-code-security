const express = require('express');
const router = express.Router();
const { noteStatements, auditStatements } = require('../db/database');
const { validate, validateQuery, validateParams, noteSchemas } = require('../utils/validation');
const { authenticate, authorizeOwnership } = require('../middleware/authenticate');
const { AppError, asyncHandler } = require('../middleware/errorHandler');
const xss = require('xss');
const logger = require('../utils/logger');

// Create a new note
router.post('/', 
  authenticate, 
  validate(noteSchemas.create), 
  asyncHandler(async (req, res) => {
    const { title, content } = req.validatedBody;
    const userId = req.user.id;
    
    // Sanitize input
    const sanitizedTitle = xss(title);
    const sanitizedContent = xss(content);
    
            try {
      const result = await noteStatements.create({
        user_id: userId,
        title: sanitizedTitle,
        content: sanitizedContent
      });
      
      const noteId = result.lastID;
      
      // Log note creation
      await auditStatements.create({
        user_id: userId,
        action: 'CREATE_NOTE',
        resource_type: 'NOTE',
        resource_id: noteId,
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      res.status(201).json({
        id: noteId,
        title: sanitizedTitle,
        content: sanitizedContent,
        user_id: userId,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Note creation error:', error);
      throw new AppError('Failed to create note', 500);
    }
  })
);

// Search notes - must be before /:id route
router.get('/search',
  authenticate,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { q } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.status(400).json({
        error: 'Search query must be at least 2 characters'
      });
    }
    
    const sanitizedQuery = xss(q.trim());
    
    try {
      // Simple search in title and content
      const { db } = require('../db/database');
      const sql = `
        SELECT * FROM notes 
        WHERE user_id = ? 
        AND is_deleted = 0
        AND (title LIKE ? OR content LIKE ?)
        ORDER BY updated_at DESC
        LIMIT 50
      `;
      
      const notes = await new Promise((resolve, reject) => {
        db.all(sql, [userId, `%${sanitizedQuery}%`, `%${sanitizedQuery}%`], (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });
      
      // Sanitize output
      const sanitizedNotes = notes.map(note => ({
        ...note,
        title: xss(note.title),
        content: xss(note.content)
      }));
      
      res.json({
        notes: sanitizedNotes,
        query: sanitizedQuery
      });
    } catch (error) {
      logger.error('Note search error:', error);
      throw new AppError('Search failed', 500);
    }
  })
);

// Get all notes for authenticated user
router.get('/', 
  authenticate,
  validateQuery(noteSchemas.pagination),
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { page, limit } = req.validatedQuery;
    const offset = (page - 1) * limit;
    
    try {
          // Get total count
    const { count } = await noteStatements.countByUser({ user_id: userId });
    
    // Get notes
    const notes = await noteStatements.findByUser({
      user_id: userId,
      limit,
      offset
    });
      
      // Sanitize output
      const sanitizedNotes = notes.map(note => ({
        ...note,
        title: xss(note.title),
        content: xss(note.content)
      }));
      
      res.json({
        notes: sanitizedNotes,
        pagination: {
          page,
          limit,
          total: count,
          totalPages: Math.ceil(count / limit)
        }
      });
    } catch (error) {
      logger.error('Notes retrieval error:', error);
      throw new AppError('Failed to retrieve notes', 500);
    }
  })
);

// Get a specific note
router.get('/:id',
  authenticate,
  validateParams(noteSchemas.id),
  authorizeOwnership('NOTE'),
  asyncHandler(async (req, res) => {
    const note = req.resource;
    
    // Log note access
    await auditStatements.create({
      user_id: req.user.id,
      action: 'READ_NOTE',
      resource_type: 'NOTE',
      resource_id: note.id,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({
      ...note,
      title: xss(note.title),
      content: xss(note.content)
    });
  })
);

// Update a note
router.put('/:id',
  authenticate,
  validateParams(noteSchemas.id),
  validate(noteSchemas.update),
  authorizeOwnership('NOTE'),
  asyncHandler(async (req, res) => {
    const noteId = req.validatedParams.id;
    const userId = req.user.id;
    const updates = req.validatedBody;
    
    // Prepare update data
    const updateData = {
      id: noteId,
      user_id: userId,
      title: updates.title ? xss(updates.title) : req.resource.title,
      content: updates.content ? xss(updates.content) : req.resource.content
    };
    
    try {
          const result = await noteStatements.update(updateData);
    
    if (result.changes === 0) {
      throw new AppError('Note not found', 404);
    }
    
    // Log note update
    await auditStatements.create({
        user_id: userId,
        action: 'UPDATE_NOTE',
        resource_type: 'NOTE',
        resource_id: noteId,
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      // Get updated note
      const updatedNote = await noteStatements.findById({
        id: noteId,
        user_id: userId
      });
      
      res.json({
        ...updatedNote,
        title: xss(updatedNote.title),
        content: xss(updatedNote.content)
      });
    } catch (error) {
      logger.error('Note update error:', error);
      throw new AppError('Failed to update note', 500);
    }
  })
);

// Delete a note (soft delete)
router.delete('/:id',
  authenticate,
  validateParams(noteSchemas.id),
  authorizeOwnership('NOTE'),
  asyncHandler(async (req, res) => {
    const noteId = req.validatedParams.id;
    const userId = req.user.id;
    
    try {
          const result = await noteStatements.softDelete({
      id: noteId,
      user_id: userId
    });
    
    if (result.changes === 0) {
      throw new AppError('Note not found', 404);
    }
    
    // Log note deletion
    await auditStatements.create({
        user_id: userId,
        action: 'DELETE_NOTE',
        resource_type: 'NOTE',
        resource_id: noteId,
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      res.json({
        message: 'Note deleted successfully'
      });
    } catch (error) {
      logger.error('Note deletion error:', error);
      throw new AppError('Failed to delete note', 500);
    }
  })
);

module.exports = router;