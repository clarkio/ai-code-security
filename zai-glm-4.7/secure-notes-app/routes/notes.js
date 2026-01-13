import express from 'express';
import { authenticateToken, authorizeNoteOwnership } from '../middleware/auth.js';
import { 
  validateCreateNote, 
  validateUpdateNote, 
  validateDeleteNote,
  validateGetNote 
} from '../middleware/validation.js';
import { 
  createNote, 
  getNoteById, 
  getNotesByUserId, 
  updateNote, 
  deleteNote 
} from '../db/index.js';

const router = express.Router();

router.post('/', authenticateToken, validateCreateNote, (req, res) => {
  try {
    const { title, content } = req.body;
    const note = createNote(req.user.id, title, content);

    res.status(201).json({
      message: 'Note created successfully',
      note
    });
  } catch (error) {
    console.error('Create note error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/', authenticateToken, (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;

    if (limit > 100) {
      return res.status(400).json({ error: 'Limit cannot exceed 100' });
    }

    if (limit < 1 || offset < 0) {
      return res.status(400).json({ error: 'Invalid pagination parameters' });
    }

    const notes = getNotesByUserId(req.user.id, limit, offset);

    res.json({
      notes,
      pagination: {
        limit,
        offset,
        count: notes.length
      }
    });
  } catch (error) {
    console.error('Get notes error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/:id', authenticateToken, validateGetNote, (req, res) => {
  try {
    const note = getNoteById(req.params.id);

    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    if (note.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({ note });
  } catch (error) {
    console.error('Get note error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/:id', authenticateToken, validateUpdateNote, (req, res) => {
  try {
    const { title, content } = req.body;

    if (!title && !content) {
      return res.status(400).json({ error: 'At least title or content must be provided' });
    }

    const existingNote = getNoteById(req.params.id);

    if (!existingNote) {
      return res.status(404).json({ error: 'Note not found' });
    }

    if (existingNote.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updatedTitle = title || existingNote.title;
    const updatedContent = content || existingNote.content;

    const note = updateNote(req.params.id, req.user.id, updatedTitle, updatedContent);

    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({
      message: 'Note updated successfully',
      note
    });
  } catch (error) {
    console.error('Update note error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/:id', authenticateToken, validateDeleteNote, (req, res) => {
  try {
    const existingNote = getNoteById(req.params.id);

    if (!existingNote) {
      return res.status(404).json({ error: 'Note not found' });
    }

    if (existingNote.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const deleted = deleteNote(req.params.id, req.user.id);

    if (!deleted) {
      return res.status(404).json({ error: 'Note not found' });
    }

    res.json({ message: 'Note deleted successfully' });
  } catch (error) {
    console.error('Delete note error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
