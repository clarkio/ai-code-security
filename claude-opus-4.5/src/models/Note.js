/**
 * Note Model
 * Handles note CRUD with parameterized queries to prevent SQL injection
 */

const { v4: uuidv4 } = require("uuid");
const xss = require("xss");
const db = require("../database");
const logger = require("../config/logger");

// XSS sanitization options
const xssOptions = {
  whiteList: {}, // No HTML tags allowed
  stripIgnoreTag: true,
  stripIgnoreTagBody: ["script"],
};

class Note {
  /**
   * Sanitize note content to prevent XSS
   */
  static sanitize(content) {
    return xss(content, xssOptions);
  }

  /**
   * Create a new note
   */
  static create(userId, title, content) {
    const id = uuidv4();
    const now = new Date().toISOString();

    // Sanitize inputs
    const sanitizedTitle = this.sanitize(title);
    const sanitizedContent = this.sanitize(content);

    const stmt = db.prepare(`
      INSERT INTO notes (id, user_id, title, content, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(id, userId, sanitizedTitle, sanitizedContent, now, now);

    logger.info(`Note created: ${id} by user: ${userId}`);

    return {
      id,
      userId,
      title: sanitizedTitle,
      content: sanitizedContent,
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * Find note by ID (only if owned by user - prevents IDOR)
   */
  static findById(noteId, userId) {
    const stmt = db.prepare(`
      SELECT id, user_id, title, content, created_at, updated_at
      FROM notes
      WHERE id = ? AND user_id = ?
    `);

    return stmt.get(noteId, userId);
  }

  /**
   * Find all notes for a user with pagination
   */
  static findByUserId(
    userId,
    { limit = 20, offset = 0, sortBy = "created_at", sortOrder = "DESC" } = {}
  ) {
    // Whitelist sort columns to prevent SQL injection
    const allowedSortColumns = ["created_at", "updated_at", "title"];
    const allowedSortOrders = ["ASC", "DESC"];

    const safeSort = allowedSortColumns.includes(sortBy)
      ? sortBy
      : "created_at";
    const safeOrder = allowedSortOrders.includes(sortOrder.toUpperCase())
      ? sortOrder.toUpperCase()
      : "DESC";

    // Ensure limit and offset are integers
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

    // Note: sort column and order are validated, so safe to interpolate
    const stmt = db.prepare(`
      SELECT id, user_id, title, content, created_at, updated_at
      FROM notes
      WHERE user_id = ?
      ORDER BY ${safeSort} ${safeOrder}
      LIMIT ? OFFSET ?
    `);

    return stmt.all(userId, safeLimit, safeOffset);
  }

  /**
   * Count total notes for a user
   */
  static countByUserId(userId) {
    const stmt = db.prepare(`
      SELECT COUNT(*) as count
      FROM notes
      WHERE user_id = ?
    `);

    const result = stmt.get(userId);
    return result.count;
  }

  /**
   * Update a note (only if owned by user)
   */
  static update(noteId, userId, { title, content }) {
    // First verify ownership
    const existing = this.findById(noteId, userId);
    if (!existing) {
      return null;
    }

    const now = new Date().toISOString();

    // Sanitize inputs
    const sanitizedTitle =
      title !== undefined ? this.sanitize(title) : existing.title;
    const sanitizedContent =
      content !== undefined ? this.sanitize(content) : existing.content;

    const stmt = db.prepare(`
      UPDATE notes
      SET title = ?, content = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `);

    stmt.run(sanitizedTitle, sanitizedContent, now, noteId, userId);

    logger.info(`Note updated: ${noteId} by user: ${userId}`);

    return {
      id: noteId,
      userId,
      title: sanitizedTitle,
      content: sanitizedContent,
      createdAt: existing.created_at,
      updatedAt: now,
    };
  }

  /**
   * Delete a note (only if owned by user)
   */
  static delete(noteId, userId) {
    // First verify ownership
    const existing = this.findById(noteId, userId);
    if (!existing) {
      return false;
    }

    const stmt = db.prepare(`
      DELETE FROM notes
      WHERE id = ? AND user_id = ?
    `);

    const result = stmt.run(noteId, userId);

    if (result.changes > 0) {
      logger.info(`Note deleted: ${noteId} by user: ${userId}`);
      return true;
    }

    return false;
  }

  /**
   * Search notes (with proper sanitization)
   */
  static search(userId, searchTerm, { limit = 20, offset = 0 } = {}) {
    // Sanitize search term and escape SQL LIKE special characters
    const sanitizedTerm = this.sanitize(searchTerm)
      .replace(/%/g, "\\%")
      .replace(/_/g, "\\_");

    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

    const stmt = db.prepare(`
      SELECT id, user_id, title, content, created_at, updated_at
      FROM notes
      WHERE user_id = ?
        AND (title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')
      ORDER BY updated_at DESC
      LIMIT ? OFFSET ?
    `);

    const searchPattern = `%${sanitizedTerm}%`;
    return stmt.all(
      userId,
      searchPattern,
      searchPattern,
      safeLimit,
      safeOffset
    );
  }
}

module.exports = Note;
