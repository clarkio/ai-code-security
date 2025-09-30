const express = require("express");
const router = express.Router();
const notesController = require("../controllers/notesController");
const { protect } = require("../middleware/auth");
const {
  noteValidation,
  idValidation,
  validate,
} = require("../middleware/validators");

// All routes require authentication
router.use(protect);

/**
 * @route   GET /api/notes
 * @desc    Get all notes for logged in user
 * @access  Private
 */
router.get("/", notesController.getNotes);

/**
 * @route   GET /api/notes/:id
 * @desc    Get single note
 * @access  Private
 */
router.get("/:id", idValidation, validate, notesController.getNote);

/**
 * @route   POST /api/notes
 * @desc    Create new note
 * @access  Private
 */
router.post("/", noteValidation, validate, notesController.createNote);

/**
 * @route   PUT /api/notes/:id
 * @desc    Update note
 * @access  Private
 */
router.put(
  "/:id",
  idValidation,
  noteValidation,
  validate,
  notesController.updateNote
);

/**
 * @route   DELETE /api/notes/:id
 * @desc    Delete note
 * @access  Private
 */
router.delete("/:id", idValidation, validate, notesController.deleteNote);

module.exports = router;
