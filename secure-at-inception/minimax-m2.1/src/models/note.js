/**
 * Notes Model
 * Handles note-related database operations with security controls
 */
const { v4: uuidv4 } = require('uuid');
const db = require('./database');
const logger = require('../utils/logger');
const InputValidator = require('../utils/validator');

class NotesModel {
  /**
   * Create a new note
   */
  static create(userId, title, content) {
    // Validate input
    const titleErrors = InputValidator.validateTitle(title);
    if (titleErrors.length > 0) {
      throw new Error(titleErrors.join(', '));
    }

    const contentErrors = InputValidator.validateContent(content);
    if (contentErrors.length > 0) {
      throw new Error(contentErrors.join(', '));
    }

    // Sanitize input
    const sanitizedTitle = InputValidator.sanitizeString(title);
    const sanitizedContent = InputValidator.sanitizeString(content);

    const noteId = uuidv4();
    
    db.run(
      `INSERT INTO notes (id, user_id, title, content) VALUES (?, ?, ?, ?)`,
      [noteId, userId, sanitizedTitle, sanitizedContent]
    );

    logger.securityEvent('note_created', { noteId, userId });

    return this.getById(noteId, userId);
  }

  /**
   * Get all notes for a user
   */
  static getAllByUserId(userId) {
    return db.query(
      `SELECT id, title, content, created_at, updated_at 
       FROM notes 
       WHERE user_id = ? 
       ORDER BY updated_at DESC`,
      [userId]
    );
  }

  /**
   * Get a single note by ID (with ownership verification)
   */
  static getById(noteId, userId) {
    // Validate UUID format
    if (!InputValidator.isValidUUID(noteId)) {
      throw new Error('Invalid note ID format');
    }

    const note = db.get(
      `SELECT id, title, content, created_at, updated_at 
       FROM notes 
       WHERE id = ? AND user_id = ?`,
      [noteId, userId]
    );

    return note;
  }

  /**
   * Update a note (with ownership verification)
   */
  static update(noteId, userId, updates) {
    // Validate UUID format
    if (!InputValidator.isValidUUID(noteId)) {
      throw new Error('Invalid note ID format');
    }

    // Verify ownership
    const existingNote = db.get(
      'SELECT id FROM notes WHERE id = ? AND user_id = ?',
      [noteId, userId]
    );

    if (!existingNote) {
      throw new Error('Note not found or access denied');
    }

    // Validate updates
    if (updates.title !== undefined) {
      const titleErrors = InputValidator.validateTitle(updates.title);
      if (titleErrors.length > 0) {
        throw new Error(titleErrors.join(', '));
      }
    }

    if (updates.content !== undefined) {
      const contentErrors = InputValidator.validateContent(updates.content);
      if (contentErrors.length > 0) {
        throw new Error(contentErrors.join(', '));
      }
    }

    // Build update query with sanitization
    const setClause = [];
    const params = [];

    if (updates.title !== undefined) {
      setClause.push('title = ?');
      params.push(InputValidator.sanitizeString(updates.title));
    }

    if (updates.content !== undefined) {
      setClause.push('content = ?');
      params.push(InputValidator.sanitizeString(updates.content));
    }

    if (setClause.length === 0) {
      return this.getById(noteId, userId);
    }

    setClause.push('updated_at = CURRENT_TIMESTAMP');
    params.push(noteId, userId);

    db.run(
      `UPDATE notes SET ${setClause.join(', ')} WHERE id = ? AND user_id = ?`,
      params
    );

    logger.securityEvent('note_updated', { noteId, userId });

    return this.getById(noteId, userId);
  }

  /**
   * Delete a note (with ownership verification)
   */
  static delete(noteId, userId) {
    // Validate UUID format
    if (!InputValidator.isValidUUID(noteId)) {
      throw new Error('Invalid note ID format');
    }

    // Verify ownership
    const existingNote = db.get(
      'SELECT id FROM notes WHERE id = ? AND user_id = ?',
      [noteId, userId]
    );

    if (!existingNote) {
      throw new Error('Note not found or access denied');
    }

    const result = db.run(
      'DELETE FROM notes WHERE id = ? AND user_id = ?',
      [noteId, userId]
    );

    logger.securityEvent('note_deleted', { noteId, userId });

    return result.changes > 0;
  }

  /**
   * Delete all notes for a user
   */
  static deleteAllByUserId(userId) {
    const result = db.run(
      'DELETE FROM notes WHERE user_id = ?',
      [userId]
    );

    logger.securityEvent('all_notes_deleted', { userId, count: result.changes });

    return result.changes;
  }
}

module.exports = NotesModel;
