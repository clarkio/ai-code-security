const databaseConnection = require('../database/connection');
const encryptionService = require('../services/encryptionService');
const logger = require('../utils/logger');

class Note {
  constructor(data = {}) {
    this.id = data.id;
    this.userId = data.user_id;
    this.title = data.title; // Plain text title (not stored)
    this.content = data.content; // Plain text content (not stored)
    this.titleEncrypted = data.title_encrypted;
    this.contentEncrypted = data.content_encrypted;
    this.encryptionIv = data.encryption_iv;
    this.createdAt = data.created_at;
    this.updatedAt = data.updated_at;
    this.isDeleted = data.is_deleted || false;
  }

  /**
   * Create a new note with encrypted content
   */
  static async create(noteData) {
    const { userId, title, content } = noteData;

    try {
      // Validate input
      Note.validateNoteData({ title, content });

      // Validate content length (before encryption)
      if (content.length > 10000) {
        throw new Error('Note content exceeds maximum length of 10,000 characters');
      }

      // Encrypt title and content
      const titleEncrypted = encryptionService.encrypt(title);
      const contentEncrypted = encryptionService.encrypt(content);

      // Insert note into database
      const query = `
        INSERT INTO notes (user_id, title_encrypted, content_encrypted, encryption_iv)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, title_encrypted, content_encrypted, encryption_iv, 
                  created_at, updated_at, is_deleted
      `;

      // Generate a unique IV for this note (stored for audit purposes)
      const encryptionIv = encryptionService.hash(`${userId}-${Date.now()}-${Math.random()}`);

      const result = await databaseConnection.query(query, [
        userId,
        titleEncrypted,
        contentEncrypted,
        encryptionIv
      ]);

      const newNote = new Note({
        ...result.rows[0],
        title,
        content
      });

      logger.security.dataModification({
        action: 'note_created',
        userId: userId,
        resource: 'note',
        resourceId: newNote.id
      });

      return newNote;

    } catch (error) {
      logger.error('Failed to create note', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Find notes by user ID with pagination
   */
  static async findByUserId(userId, options = {}) {
    try {
      const { limit = 50, offset = 0, includeDeleted = false } = options;

      let query = `
        SELECT id, user_id, title_encrypted, content_encrypted, encryption_iv,
               created_at, updated_at, is_deleted
        FROM notes 
        WHERE user_id = $1
      `;

      const params = [userId];

      if (!includeDeleted) {
        query += ' AND is_deleted = false';
      }

      query += ' ORDER BY created_at DESC LIMIT $2 OFFSET $3';
      params.push(limit, offset);

      const result = await databaseConnection.query(query, params);

      const notes = result.rows.map(row => {
        try {
          // Decrypt title and content
          const title = encryptionService.decrypt(row.title_encrypted);
          const content = encryptionService.decrypt(row.content_encrypted);

          return new Note({
            ...row,
            title,
            content
          });
        } catch (decryptError) {
          logger.error('Failed to decrypt note', {
            error: decryptError.message,
            noteId: row.id,
            userId
          });
          
          // Return note with decryption error indicators
          return new Note({
            ...row,
            title: '[DECRYPTION_ERROR]',
            content: '[DECRYPTION_ERROR]'
          });
        }
      });

      logger.security.dataAccess({
        action: 'notes_retrieved',
        userId: userId,
        resource: 'note',
        count: notes.length
      });

      return notes;

    } catch (error) {
      logger.error('Failed to find notes by user ID', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Find note by ID and user ID (ensures ownership)
   */
  static async findByIdAndUserId(noteId, userId) {
    try {
      const query = `
        SELECT id, user_id, title_encrypted, content_encrypted, encryption_iv,
               created_at, updated_at, is_deleted
        FROM notes 
        WHERE id = $1 AND user_id = $2 AND is_deleted = false
      `;

      const result = await databaseConnection.query(query, [noteId, userId]);

      if (result.rows.length === 0) {
        return null;
      }

      const noteData = result.rows[0];

      try {
        // Decrypt title and content
        const title = encryptionService.decrypt(noteData.title_encrypted);
        const content = encryptionService.decrypt(noteData.content_encrypted);

        const note = new Note({
          ...noteData,
          title,
          content
        });

        logger.security.dataAccess({
          action: 'note_retrieved',
          userId: userId,
          resource: 'note',
          resourceId: noteId
        });

        return note;

      } catch (decryptError) {
        logger.error('Failed to decrypt note', {
          error: decryptError.message,
          noteId,
          userId
        });
        throw new Error('Failed to decrypt note content');
      }

    } catch (error) {
      logger.error('Failed to find note by ID and user ID', {
        error: error.message,
        noteId,
        userId
      });
      throw error;
    }
  }

  /**
   * Update note content
   */
  async update(updateData) {
    try {
      const { title, content } = updateData;

      // Validate input
      if (title !== undefined || content !== undefined) {
        Note.validateNoteData({ 
          title: title || this.title, 
          content: content || this.content 
        });
      }

      // Validate content length (before encryption)
      const newContent = content !== undefined ? content : this.content;
      if (newContent.length > 10000) {
        throw new Error('Note content exceeds maximum length of 10,000 characters');
      }

      // Prepare update fields
      const updates = [];
      const params = [];
      let paramIndex = 1;

      if (title !== undefined) {
        const titleEncrypted = encryptionService.encrypt(title);
        updates.push(`title_encrypted = $${paramIndex++}`);
        params.push(titleEncrypted);
        this.title = title;
        this.titleEncrypted = titleEncrypted;
      }

      if (content !== undefined) {
        const contentEncrypted = encryptionService.encrypt(content);
        updates.push(`content_encrypted = $${paramIndex++}`);
        params.push(contentEncrypted);
        this.content = content;
        this.contentEncrypted = contentEncrypted;
      }

      if (updates.length === 0) {
        return this; // No updates to perform
      }

      updates.push(`updated_at = CURRENT_TIMESTAMP`);
      params.push(this.id, this.userId);

      const query = `
        UPDATE notes 
        SET ${updates.join(', ')}
        WHERE id = $${paramIndex++} AND user_id = $${paramIndex++} AND is_deleted = false
        RETURNING updated_at
      `;

      const result = await databaseConnection.query(query, params);

      if (result.rows.length === 0) {
        throw new Error('Note not found or access denied');
      }

      this.updatedAt = result.rows[0].updated_at;

      logger.security.dataModification({
        action: 'note_updated',
        userId: this.userId,
        resource: 'note',
        resourceId: this.id,
        changes: Object.keys(updateData)
      });

      return this;

    } catch (error) {
      logger.error('Failed to update note', {
        error: error.message,
        noteId: this.id,
        userId: this.userId
      });
      throw error;
    }
  }

  /**
   * Soft delete note
   */
  async delete() {
    try {
      const query = `
        UPDATE notes 
        SET is_deleted = true, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND user_id = $2 AND is_deleted = false
        RETURNING updated_at
      `;

      const result = await databaseConnection.query(query, [this.id, this.userId]);

      if (result.rows.length === 0) {
        throw new Error('Note not found or access denied');
      }

      this.isDeleted = true;
      this.updatedAt = result.rows[0].updated_at;

      logger.security.dataModification({
        action: 'note_deleted',
        userId: this.userId,
        resource: 'note',
        resourceId: this.id
      });

      return this;

    } catch (error) {
      logger.error('Failed to delete note', {
        error: error.message,
        noteId: this.id,
        userId: this.userId
      });
      throw error;
    }
  }

  /**
   * Permanently delete note (hard delete)
   */
  async permanentDelete() {
    try {
      const query = `
        DELETE FROM notes 
        WHERE id = $1 AND user_id = $2
      `;

      const result = await databaseConnection.query(query, [this.id, this.userId]);

      if (result.rowCount === 0) {
        throw new Error('Note not found or access denied');
      }

      logger.security.dataModification({
        action: 'note_permanently_deleted',
        userId: this.userId,
        resource: 'note',
        resourceId: this.id
      });

      return true;

    } catch (error) {
      logger.error('Failed to permanently delete note', {
        error: error.message,
        noteId: this.id,
        userId: this.userId
      });
      throw error;
    }
  }

  /**
   * Restore soft-deleted note
   */
  async restore() {
    try {
      const query = `
        UPDATE notes 
        SET is_deleted = false, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND user_id = $2 AND is_deleted = true
        RETURNING updated_at
      `;

      const result = await databaseConnection.query(query, [this.id, this.userId]);

      if (result.rows.length === 0) {
        throw new Error('Note not found or not deleted');
      }

      this.isDeleted = false;
      this.updatedAt = result.rows[0].updated_at;

      logger.security.dataModification({
        action: 'note_restored',
        userId: this.userId,
        resource: 'note',
        resourceId: this.id
      });

      return this;

    } catch (error) {
      logger.error('Failed to restore note', {
        error: error.message,
        noteId: this.id,
        userId: this.userId
      });
      throw error;
    }
  }

  /**
   * Get note count for user
   */
  static async getCountByUserId(userId, includeDeleted = false) {
    try {
      let query = 'SELECT COUNT(*) as count FROM notes WHERE user_id = $1';
      const params = [userId];

      if (!includeDeleted) {
        query += ' AND is_deleted = false';
      }

      const result = await databaseConnection.query(query, params);
      return parseInt(result.rows[0].count, 10);

    } catch (error) {
      logger.error('Failed to get note count', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Search notes by content (requires decryption)
   */
  static async searchByUserId(userId, searchTerm, options = {}) {
    try {
      const { limit = 50, offset = 0 } = options;

      // First, get all notes for the user
      const allNotes = await Note.findByUserId(userId, { 
        limit: 1000, // Reasonable limit for search
        offset: 0,
        includeDeleted: false 
      });

      // Filter notes that contain the search term (case-insensitive)
      const matchingNotes = allNotes.filter(note => {
        const titleMatch = note.title.toLowerCase().includes(searchTerm.toLowerCase());
        const contentMatch = note.content.toLowerCase().includes(searchTerm.toLowerCase());
        return titleMatch || contentMatch;
      });

      // Apply pagination to results
      const paginatedNotes = matchingNotes.slice(offset, offset + limit);

      logger.security.dataAccess({
        action: 'notes_searched',
        userId: userId,
        resource: 'note',
        searchTerm: '[REDACTED]',
        resultCount: paginatedNotes.length
      });

      return paginatedNotes;

    } catch (error) {
      logger.error('Failed to search notes', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Get note data for JSON serialization (excludes encrypted fields)
   */
  toJSON() {
    return {
      id: this.id,
      userId: this.userId,
      title: this.title,
      content: this.content,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      isDeleted: this.isDeleted
    };
  }

  // Static utility methods

  /**
   * Validate note data
   */
  static validateNoteData(noteData) {
    const { title, content } = noteData;

    if (!title || typeof title !== 'string' || title.trim().length === 0) {
      throw new Error('Note title is required and must be a non-empty string');
    }

    if (title.length > 255) {
      throw new Error('Note title cannot exceed 255 characters');
    }

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      throw new Error('Note content is required and must be a non-empty string');
    }

    if (content.length > 10000) {
      throw new Error('Note content cannot exceed 10,000 characters');
    }

    // Basic XSS prevention - check for script tags
    const scriptRegex = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
    if (scriptRegex.test(title) || scriptRegex.test(content)) {
      throw new Error('Script tags are not allowed in note content');
    }
  }
}

module.exports = Note;