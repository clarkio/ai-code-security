const { v4: uuidv4 } = require("uuid");
const Note = require("../models/Note");
const { ErrorResponse } = require("../middleware/errorHandler");

/**
 * @desc    Get all notes for user
 * @route   GET /api/notes
 * @access  Private
 */
exports.getNotes = async (req, res, next) => {
  try {
    const notes = Note.findByUserId(req.user.id);

    res.status(200).json({
      success: true,
      count: notes.length,
      data: notes,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get single note
 * @route   GET /api/notes/:id
 * @access  Private
 */
exports.getNote = async (req, res, next) => {
  try {
    const note = Note.findById(req.params.id);

    if (!note) {
      return res.status(404).json({
        success: false,
        message: "Note not found",
      });
    }

    // Make sure user owns note
    if (note.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "Not authorized to access this note",
      });
    }

    res.status(200).json({
      success: true,
      data: note,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Create new note
 * @route   POST /api/notes
 * @access  Private
 */
exports.createNote = async (req, res, next) => {
  try {
    const { title, content } = req.body;

    // Check user's note limit (prevent abuse)
    const userNotes = Note.findByUserId(req.user.id);
    if (userNotes.length >= 1000) {
      return res.status(400).json({
        success: false,
        message: "Maximum number of notes reached (1000)",
      });
    }

    const note = {
      id: uuidv4(),
      userId: req.user.id,
      title,
      content,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    Note.create(note);

    res.status(201).json({
      success: true,
      data: note,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Update note
 * @route   PUT /api/notes/:id
 * @access  Private
 */
exports.updateNote = async (req, res, next) => {
  try {
    let note = Note.findById(req.params.id);

    if (!note) {
      return res.status(404).json({
        success: false,
        message: "Note not found",
      });
    }

    // Make sure user owns note
    if (note.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "Not authorized to update this note",
      });
    }

    const { title, content } = req.body;

    note = Note.update(req.params.id, {
      title,
      content,
      updatedAt: new Date().toISOString(),
    });

    res.status(200).json({
      success: true,
      data: note,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Delete note
 * @route   DELETE /api/notes/:id
 * @access  Private
 */
exports.deleteNote = async (req, res, next) => {
  try {
    const note = Note.findById(req.params.id);

    if (!note) {
      return res.status(404).json({
        success: false,
        message: "Note not found",
      });
    }

    // Make sure user owns note
    if (note.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "Not authorized to delete this note",
      });
    }

    Note.delete(req.params.id);

    res.status(200).json({
      success: true,
      data: {},
    });
  } catch (err) {
    next(err);
  }
};
