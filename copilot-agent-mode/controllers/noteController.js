const { validationResult } = require("express-validator");
const Note = require("../models/Note");
const { asyncHandler } = require("../utils/asyncHandler");
const { AppError } = require("../middleware/errorMiddleware");

// Get all notes for a user
exports.getNotes = asyncHandler(async (req, res, next) => {
  // Implement pagination
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const skip = (page - 1) * limit;

  // Get only current user's notes
  const notes = await Note.find({ user: req.user.id })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

  // Count total documents for pagination info
  const totalNotes = await Note.countDocuments({ user: req.user.id });

  res.status(200).json({
    status: "success",
    results: notes.length,
    pagination: {
      page,
      pages: Math.ceil(totalNotes / limit),
      count: totalNotes,
    },
    data: {
      notes,
    },
  });
});

// Get a single note
exports.getNote = asyncHandler(async (req, res, next) => {
  const note = await Note.findOne({
    _id: req.params.id,
    user: req.user.id, // Ensure the note belongs to the current user
  });

  if (!note) {
    return next(new AppError("Note not found", 404));
  }

  res.status(200).json({
    status: "success",
    data: {
      note,
    },
  });
});

// Create a new note
exports.createNote = asyncHandler(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new AppError(
        "Validation error: " +
          errors
            .array()
            .map((e) => e.msg)
            .join(", "),
        400
      )
    );
  }

  // Create note with user reference
  const newNote = await Note.create({
    title: req.body.title,
    content: req.body.content,
    user: req.user.id,
  });

  res.status(201).json({
    status: "success",
    data: {
      note: newNote,
    },
  });
});

// Update a note
exports.updateNote = asyncHandler(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new AppError(
        "Validation error: " +
          errors
            .array()
            .map((e) => e.msg)
            .join(", "),
        400
      )
    );
  }

  // Find and update note - ensuring it belongs to the current user
  const note = await Note.findOneAndUpdate(
    { _id: req.params.id, user: req.user.id },
    { title: req.body.title, content: req.body.content },
    {
      new: true, // Return the updated note
      runValidators: true, // Run model validators
    }
  );

  if (!note) {
    return next(new AppError("Note not found", 404));
  }

  res.status(200).json({
    status: "success",
    data: {
      note,
    },
  });
});

// Delete a note
exports.deleteNote = asyncHandler(async (req, res, next) => {
  // Find and delete note - ensuring it belongs to the current user
  const note = await Note.findOneAndDelete({
    _id: req.params.id,
    user: req.user.id,
  });

  if (!note) {
    return next(new AppError("Note not found", 404));
  }

  res.status(204).json({
    status: "success",
    data: null,
  });
});
