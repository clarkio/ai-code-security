"use strict";

/**
 * Notes API routes.
 *
 * SECURITY:
 *  - All routes require authentication (requireAuth).
 *  - Every DB operation is scoped by req.user.id (IDOR protection).
 *  - Write operations are rate-limited (writeLimiter).
 *  - CSRF token is verified on all state-changing requests.
 *  - Input is validated & sanitized (noteRules).
 */

const express = require("express");

const router = express.Router();
const repo = require("../db/repository");
const { requireAuth } = require("../middleware/auth");
const {
  noteRules,
  handleValidationErrors,
} = require("../middleware/validation");
const { writeLimiter } = require("../config/security");

// Validate that a note id parameter is a positive integer string.
// parseInt('1 OR 1=1') returns 1, so we must check the raw string too.
function parseNoteId(param) {
  if (!/^\d+$/.test(param)) return null;
  const id = parseInt(param, 10);
  if (!Number.isInteger(id) || id < 1) return null;
  return id;
}

// All note routes require auth
router.use(requireAuth);

// --- List notes ---
router.get("/", (req, res, next) => {
  try {
    const notes = repo.listNotes(req.user.id);
    return res.json({ notes });
  } catch (err) {
    return next(err);
  }
});

// --- Get single note ---
router.get("/:id", (req, res, next) => {
  try {
    const noteId = parseNoteId(req.params.id);
    if (!noteId) {
      return res.status(400).json({ error: "Invalid note id" });
    }
    const note = repo.getNote(req.user.id, noteId);
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    return res.json({ note });
  } catch (err) {
    return next(err);
  }
});

// --- Create note ---
router.post(
  "/",
  writeLimiter,
  noteRules,
  handleValidationErrors,
  (req, res, next) => {
    try {
      const { title, body } = req.body;
      const id = repo.createNote(req.user.id, title, body);
      return res.status(201).json({ message: "Note created", id });
    } catch (err) {
      return next(err);
    }
  },
);

// --- Update note ---
router.put(
  "/:id",
  writeLimiter,
  noteRules,
  handleValidationErrors,
  (req, res, next) => {
    try {
      const noteId = parseNoteId(req.params.id);
      if (!noteId) {
        return res.status(400).json({ error: "Invalid note id" });
      }
      const { title, body } = req.body;
      const updated = repo.updateNote(req.user.id, noteId, title, body);
      if (!updated) {
        return res.status(404).json({ error: "Note not found" });
      }
      return res.json({ message: "Note updated" });
    } catch (err) {
      return next(err);
    }
  },
);

// --- Delete note ---
router.delete("/:id", writeLimiter, (req, res, next) => {
  try {
    const noteId = parseNoteId(req.params.id);
    if (!noteId) {
      return res.status(400).json({ error: "Invalid note id" });
    }
    const deleted = repo.deleteNote(req.user.id, noteId);
    if (!deleted) {
      return res.status(404).json({ error: "Note not found" });
    }
    return res.json({ message: "Note deleted" });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
