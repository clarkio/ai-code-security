/**
 * Notes Routes
 * Secure CRUD operations for notes
 */

const express = require("express");
const router = express.Router();

const Note = require("../models/Note");
const { AuditLog, AUDIT_ACTIONS } = require("../models/AuditLog");
const { authenticate } = require("../middleware/auth");
const { handleValidationErrors } = require("../middleware/validation");
const {
  createNoteValidation,
  updateNoteValidation,
  noteIdValidation,
  paginationValidation,
  searchValidation,
} = require("../validators");
const logger = require("../config/logger");

// All notes routes require authentication
router.use(authenticate);

/**
 * GET /api/notes
 * Get all notes for the authenticated user
 */
router.get("/", paginationValidation, handleValidationErrors, (req, res) => {
  try {
    const { limit, offset, sortBy, sortOrder } = req.query;

    const notes = Note.findByUserId(req.user.id, {
      limit,
      offset,
      sortBy,
      sortOrder,
    });

    const total = Note.countByUserId(req.user.id);

    res.json({
      notes,
      pagination: {
        total,
        limit: limit || 20,
        offset: offset || 0,
        hasMore: (offset || 0) + notes.length < total,
      },
    });
  } catch (error) {
    logger.error("Get notes error:", error);
    res.status(500).json({
      error: "Failed to retrieve notes",
    });
  }
});

/**
 * GET /api/notes/search
 * Search notes
 */
router.get("/search", searchValidation, handleValidationErrors, (req, res) => {
  try {
    const { q, limit, offset } = req.query;

    const notes = Note.search(req.user.id, q, { limit, offset });

    res.json({
      notes,
      query: q,
    });
  } catch (error) {
    logger.error("Search notes error:", error);
    res.status(500).json({
      error: "Search failed",
    });
  }
});

/**
 * GET /api/notes/:id
 * Get a specific note
 */
router.get("/:id", noteIdValidation, handleValidationErrors, (req, res) => {
  try {
    // Authorization check is built into findById (only returns if user owns it)
    const note = Note.findById(req.params.id, req.user.id);

    if (!note) {
      return res.status(404).json({
        error: "Note not found",
      });
    }

    res.json({ note });
  } catch (error) {
    logger.error("Get note error:", error);
    res.status(500).json({
      error: "Failed to retrieve note",
    });
  }
});

/**
 * POST /api/notes
 * Create a new note
 */
router.post("/", createNoteValidation, handleValidationErrors, (req, res) => {
  try {
    const { title, content } = req.body;

    const note = Note.create(req.user.id, title, content);

    // Audit log
    AuditLog.log(AUDIT_ACTIONS.NOTE_CREATE, {
      userId: req.user.id,
      resource: "note",
      resourceId: note.id,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    });

    res.status(201).json({
      message: "Note created successfully",
      note,
    });
  } catch (error) {
    logger.error("Create note error:", error);
    res.status(500).json({
      error: "Failed to create note",
    });
  }
});

/**
 * PUT /api/notes/:id
 * Update a note
 */
router.put("/:id", updateNoteValidation, handleValidationErrors, (req, res) => {
  try {
    const { title, content } = req.body;

    // Authorization check is built into update (only updates if user owns it)
    const note = Note.update(req.params.id, req.user.id, { title, content });

    if (!note) {
      return res.status(404).json({
        error: "Note not found",
      });
    }

    // Audit log
    AuditLog.log(AUDIT_ACTIONS.NOTE_UPDATE, {
      userId: req.user.id,
      resource: "note",
      resourceId: note.id,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    });

    res.json({
      message: "Note updated successfully",
      note,
    });
  } catch (error) {
    logger.error("Update note error:", error);
    res.status(500).json({
      error: "Failed to update note",
    });
  }
});

/**
 * DELETE /api/notes/:id
 * Delete a note
 */
router.delete("/:id", noteIdValidation, handleValidationErrors, (req, res) => {
  try {
    // Authorization check is built into delete (only deletes if user owns it)
    const deleted = Note.delete(req.params.id, req.user.id);

    if (!deleted) {
      return res.status(404).json({
        error: "Note not found",
      });
    }

    // Audit log
    AuditLog.log(AUDIT_ACTIONS.NOTE_DELETE, {
      userId: req.user.id,
      resource: "note",
      resourceId: req.params.id,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    });

    res.json({
      message: "Note deleted successfully",
    });
  } catch (error) {
    logger.error("Delete note error:", error);
    res.status(500).json({
      error: "Failed to delete note",
    });
  }
});

module.exports = router;
