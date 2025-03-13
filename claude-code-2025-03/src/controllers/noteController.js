const Note = require('../models/note');
const createError = require('http-errors');
const mongoose = require('mongoose');

// Helper to validate ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// Get all notes for current user
const getNotes = async (req, res, next) => {
  try {
    const userId = req.session.user.id;
    
    const notes = await Note.find({ userId })
      .sort({ updatedAt: -1 })
      .limit(100);
    
    res.json({
      success: true,
      count: notes.length,
      notes: notes.map(note => note.toJSON()),
    });
  } catch (error) {
    next(error);
  }
};

// Get a single note by ID
const getNoteById = async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const userId = req.session.user.id;
    
    // Validate ID format
    if (!isValidObjectId(noteId)) {
      return next(createError(400, 'Invalid note ID format'));
    }
    
    const note = await Note.findById(noteId);
    
    // Check if note exists
    if (!note) {
      return next(createError(404, 'Note not found'));
    }
    
    // Set resource user ID for ownership check
    req.resourceUserId = note.userId;
    
    // Note: isResourceOwner middleware will run after this
    // and verify the note belongs to the current user
    
    res.json({
      success: true,
      note: note.toJSON(),
    });
  } catch (error) {
    next(error);
  }
};

// Create a new note
const createNote = async (req, res, next) => {
  try {
    const { title, content } = req.body;
    const userId = req.session.user.id;
    
    const note = new Note({
      title,
      content,
      userId,
    });
    
    const savedNote = await note.save();
    
    res.status(201).json({
      success: true,
      message: 'Note created successfully',
      note: savedNote.toJSON(),
    });
  } catch (error) {
    next(error);
  }
};

// Update a note
const updateNote = async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const userId = req.session.user.id;
    const { title, content } = req.body;
    
    // Validate ID format
    if (!isValidObjectId(noteId)) {
      return next(createError(400, 'Invalid note ID format'));
    }
    
    // Find note
    const note = await Note.findById(noteId);
    
    // Check if note exists
    if (!note) {
      return next(createError(404, 'Note not found'));
    }
    
    // Check if user owns the note
    if (note.userId.toString() !== userId) {
      return next(createError(403, 'Access denied'));
    }
    
    // Update the note
    note.title = title;
    note.content = content;
    
    const updatedNote = await note.save();
    
    res.json({
      success: true,
      message: 'Note updated successfully',
      note: updatedNote.toJSON(),
    });
  } catch (error) {
    next(error);
  }
};

// Delete a note
const deleteNote = async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const userId = req.session.user.id;
    
    // Validate ID format
    if (!isValidObjectId(noteId)) {
      return next(createError(400, 'Invalid note ID format'));
    }
    
    // Find note
    const note = await Note.findById(noteId);
    
    // Check if note exists
    if (!note) {
      return next(createError(404, 'Note not found'));
    }
    
    // Check if user owns the note
    if (note.userId.toString() !== userId) {
      return next(createError(403, 'Access denied'));
    }
    
    // Delete the note
    await note.deleteOne();
    
    res.json({
      success: true,
      message: 'Note deleted successfully',
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getNotes,
  getNoteById,
  createNote,
  updateNote,
  deleteNote,
};