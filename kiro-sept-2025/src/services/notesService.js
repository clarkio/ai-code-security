const Note = require('../models/Note');
const logger = require('../utils/logger');
const { validateInput, schemas } = require('../middleware/validation');

class NotesService {
  constructor() {
    this.maxNotesPerUser = 1000; // Reasonable limit per user
    this.maxContentLength = 10000; // Characters
    this.maxTitleLength = 200; // Characters
  }

  /**
   * Create a new note with user ownership assignment and encryption
   */
  async createNote(userId, noteData) {
    try {
      const { title, content } = noteData;

      // Validate input data
      this.validateNoteData({ title, content });

      // Check user's note count limit
      const userNoteCount = await Note.getCountByUserId(userId);
      if (userNoteCount >= this.maxNotesPerUser) {
        throw new Error(`Maximum number of notes (${this.maxNotesPerUser}) reached for this user`);
      }

      // Create note with encrypted content
      const note = await Note.create({
        userId,
        title: title.trim(),
        content: content.trim()
      });

      logger.security.dataModification({
        action: 'note_created',
        userId: userId,
        resource: 'note',
        resourceId: note.id,
        metadata: {
          titleLength: title.length,
          contentLength: content.length
        }
      });

      return {
        id: note.id,
        title: note.title,
        content: note.content,
        createdAt: note.createdAt,
        updatedAt: note.updatedAt
      };

    } catch (error) {
      logger.error('Failed to create note', {
        error: error.message,
        userId,
        titleLength: noteData.title?.length,
        contentLength: noteData.content?.length
      });

      // Re-throw validation errors with original message
      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to create note. Please try again.');
    }
  }

  /**
   * Get notes for a user with pagination and authorization
   */
  async getNotes(userId, options = {}) {
    try {
      const {
        page = 1,
        limit = 10,
        includeDeleted = false
      } = options;

      // Validate pagination parameters
      this.validatePaginationParams({ page, limit });

      // Calculate offset
      const offset = (page - 1) * limit;

      // Get notes with pagination
      const notes = await Note.findByUserId(userId, {
        limit,
        offset,
        includeDeleted
      });

      // Get total count for pagination metadata
      const totalCount = await Note.getCountByUserId(userId, includeDeleted);
      const totalPages = Math.ceil(totalCount / limit);

      logger.security.dataAccess({
        action: 'notes_retrieved',
        userId: userId,
        resource: 'note',
        count: notes.length,
        pagination: { page, limit, totalCount }
      });

      return {
        notes: notes.map(note => ({
          id: note.id,
          title: note.title,
          content: note.content,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
          isDeleted: note.isDeleted
        })),
        pagination: {
          page,
          limit,
          totalCount,
          totalPages,
          hasNextPage: page < totalPages,
          hasPreviousPage: page > 1
        }
      };

    } catch (error) {
      logger.error('Failed to get notes', {
        error: error.message,
        userId,
        options
      });

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to retrieve notes. Please try again.');
    }
  }

  /**
   * Get a single note by ID with ownership verification
   */
  async getNote(userId, noteId) {
    try {
      // Validate note ID format
      this.validateNoteId(noteId);

      // Find note with ownership verification
      const note = await Note.findByIdAndUserId(noteId, userId);

      if (!note) {
        throw new Error('Note not found or access denied');
      }

      logger.security.dataAccess({
        action: 'note_retrieved',
        userId: userId,
        resource: 'note',
        resourceId: noteId
      });

      return {
        id: note.id,
        title: note.title,
        content: note.content,
        createdAt: note.createdAt,
        updatedAt: note.updatedAt,
        isDeleted: note.isDeleted
      };

    } catch (error) {
      logger.error('Failed to get note', {
        error: error.message,
        userId,
        noteId
      });

      if (error.message.includes('not found') || error.message.includes('access denied')) {
        throw error;
      }

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to retrieve note. Please try again.');
    }
  }

  /**
   * Update a note with ownership verification and encrypted storage
   */
  async updateNote(userId, noteId, updateData) {
    try {
      const { title, content } = updateData;

      // Validate note ID format
      this.validateNoteId(noteId);

      // Validate update data (at least one field must be provided)
      if (!title && !content && title !== '' && content !== '') {
        throw new Error('At least one field (title or content) must be provided for update');
      }

      // Validate provided fields
      if (title !== undefined) {
        this.validateTitle(title);
      }
      if (content !== undefined) {
        this.validateContent(content);
      }

      // Find note with ownership verification
      const note = await Note.findByIdAndUserId(noteId, userId);

      if (!note) {
        throw new Error('Note not found or access denied');
      }

      // Prepare update data
      const cleanUpdateData = {};
      if (title !== undefined) {
        cleanUpdateData.title = title.trim();
      }
      if (content !== undefined) {
        cleanUpdateData.content = content.trim();
      }

      // Update note
      const updatedNote = await note.update(cleanUpdateData);

      logger.security.dataModification({
        action: 'note_updated',
        userId: userId,
        resource: 'note',
        resourceId: noteId,
        changes: Object.keys(cleanUpdateData),
        metadata: {
          titleLength: cleanUpdateData.title?.length,
          contentLength: cleanUpdateData.content?.length
        }
      });

      return {
        id: updatedNote.id,
        title: updatedNote.title,
        content: updatedNote.content,
        createdAt: updatedNote.createdAt,
        updatedAt: updatedNote.updatedAt
      };

    } catch (error) {
      logger.error('Failed to update note', {
        error: error.message,
        userId,
        noteId,
        updateFields: Object.keys(updateData)
      });

      if (error.message.includes('not found') || error.message.includes('access denied')) {
        throw error;
      }

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to update note. Please try again.');
    }
  }

  /**
   * Delete a note with soft delete and audit logging
   */
  async deleteNote(userId, noteId) {
    try {
      // Validate note ID format
      this.validateNoteId(noteId);

      // Find note with ownership verification
      const note = await Note.findByIdAndUserId(noteId, userId);

      if (!note) {
        throw new Error('Note not found or access denied');
      }

      // Soft delete the note
      await note.delete();

      logger.security.dataModification({
        action: 'note_deleted',
        userId: userId,
        resource: 'note',
        resourceId: noteId,
        metadata: {
          deletionType: 'soft_delete'
        }
      });

      return {
        success: true,
        message: 'Note deleted successfully',
        noteId: noteId
      };

    } catch (error) {
      logger.error('Failed to delete note', {
        error: error.message,
        userId,
        noteId
      });

      if (error.message.includes('not found') || error.message.includes('access denied')) {
        throw error;
      }

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to delete note. Please try again.');
    }
  }

  /**
   * Search notes by content with authorization
   */
  async searchNotes(userId, searchTerm, options = {}) {
    try {
      const { page = 1, limit = 10 } = options;

      // Validate search term
      if (!searchTerm || typeof searchTerm !== 'string') {
        throw new Error('Search term is required and must be a string');
      }

      if (searchTerm.length < 2) {
        throw new Error('Search term must be at least 2 characters long');
      }

      if (searchTerm.length > 100) {
        throw new Error('Search term is too long (maximum 100 characters)');
      }

      // Validate pagination parameters
      this.validatePaginationParams({ page, limit });

      // Calculate offset
      const offset = (page - 1) * limit;

      // Search notes
      const notes = await Note.searchByUserId(userId, searchTerm.trim(), {
        limit,
        offset
      });

      logger.security.dataAccess({
        action: 'notes_searched',
        userId: userId,
        resource: 'note',
        resultCount: notes.length,
        searchTermLength: searchTerm.length,
        pagination: { page, limit }
      });

      return {
        notes: notes.map(note => ({
          id: note.id,
          title: note.title,
          content: note.content,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt
        })),
        searchTerm: searchTerm,
        pagination: {
          page,
          limit,
          resultCount: notes.length
        }
      };

    } catch (error) {
      logger.error('Failed to search notes', {
        error: error.message,
        userId,
        searchTermLength: searchTerm?.length
      });

      if (this.isValidationError(error)) {
        throw error;
      }

      throw new Error('Failed to search notes. Please try again.');
    }
  }

  /**
   * Get user's note statistics
   */
  async getNoteStats(userId) {
    try {
      const totalNotes = await Note.getCountByUserId(userId, false);
      const deletedNotes = await Note.getCountByUserId(userId, true) - totalNotes;

      logger.security.dataAccess({
        action: 'note_stats_retrieved',
        userId: userId,
        resource: 'note',
        metadata: {
          totalNotes,
          deletedNotes
        }
      });

      return {
        totalNotes,
        deletedNotes,
        maxNotesAllowed: this.maxNotesPerUser,
        remainingNotes: Math.max(0, this.maxNotesPerUser - totalNotes)
      };

    } catch (error) {
      logger.error('Failed to get note statistics', {
        error: error.message,
        userId
      });

      throw new Error('Failed to retrieve note statistics. Please try again.');
    }
  }

  // Validation helper methods

  /**
   * Validate note data for creation
   */
  validateNoteData({ title, content }) {
    this.validateTitle(title);
    this.validateContent(content);
  }

  /**
   * Validate note title
   */
  validateTitle(title) {
    if (!title || typeof title !== 'string') {
      throw new Error('Note title is required and must be a string');
    }

    if (title.trim().length === 0) {
      throw new Error('Note title cannot be empty');
    }

    if (title.length > this.maxTitleLength) {
      throw new Error(`Note title cannot exceed ${this.maxTitleLength} characters`);
    }

    // Check for potentially malicious content
    if (this.containsSuspiciousContent(title)) {
      throw new Error('Note title contains potentially harmful content');
    }
  }

  /**
   * Validate note content
   */
  validateContent(content) {
    if (content === undefined || content === null) {
      throw new Error('Note content is required');
    }

    if (typeof content !== 'string') {
      throw new Error('Note content must be a string');
    }

    if (content.length > this.maxContentLength) {
      throw new Error(`Note content cannot exceed ${this.maxContentLength} characters`);
    }

    // Check for potentially malicious content
    if (this.containsSuspiciousContent(content)) {
      throw new Error('Note content contains potentially harmful content');
    }
  }

  /**
   * Validate note ID format
   */
  validateNoteId(noteId) {
    if (!noteId || typeof noteId !== 'string') {
      throw new Error('Note ID is required and must be a string');
    }

    // Basic UUID format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(noteId)) {
      throw new Error('Invalid note ID format');
    }
  }

  /**
   * Validate pagination parameters
   */
  validatePaginationParams({ page, limit }) {
    if (page !== undefined) {
      if (!Number.isInteger(page) || page < 1) {
        throw new Error('Page must be a positive integer');
      }
      if (page > 1000) {
        throw new Error('Page number is too large (maximum 1000)');
      }
    }

    if (limit !== undefined) {
      if (!Number.isInteger(limit) || limit < 1) {
        throw new Error('Limit must be a positive integer');
      }
      if (limit > 100) {
        throw new Error('Limit cannot exceed 100');
      }
    }
  }

  /**
   * Check for suspicious content patterns
   */
  containsSuspiciousContent(text) {
    const suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /onclick\s*=/gi,
      /eval\s*\(/gi,
      /document\.cookie/gi,
      /document\.write/gi
    ];

    return suspiciousPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Check if error is a validation error
   */
  isValidationError(error) {
    const validationMessages = [
      'is required',
      'must be',
      'cannot be',
      'cannot exceed',
      'is too',
      'invalid',
      'format',
      'contains',
      'harmful',
      'suspicious',
      'malicious',
      'maximum'
    ];

    return validationMessages.some(msg => 
      error.message.toLowerCase().includes(msg.toLowerCase())
    );
  }

  /**
   * Get service configuration and status
   */
  getStatus() {
    return {
      maxNotesPerUser: this.maxNotesPerUser,
      maxContentLength: this.maxContentLength,
      maxTitleLength: this.maxTitleLength,
      validationEnabled: true,
      encryptionEnabled: true,
      auditLoggingEnabled: true
    };
  }
}

// Create singleton instance
const notesService = new NotesService();

module.exports = notesService;