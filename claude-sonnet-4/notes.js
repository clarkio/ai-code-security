const { validationResult } = require('express-validator')
const xss = require('xss')
const database = require('./database')

class NotesController {
  // Get all notes for authenticated user
  static async getAllNotes (req, res) {
    try {
      const userId = req.user.userId

      const notes = await database.all(
        'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC',
        [userId]
      )

      // Sanitize output to prevent XSS
      const sanitizedNotes = notes.map((note) => ({
        id: note.id,
        title: xss(note.title),
        content: xss(note.content),
        created_at: note.created_at,
        updated_at: note.updated_at
      }))

      res.json({
        success: true,
        notes: sanitizedNotes
      })
    } catch (error) {
      console.error('Get notes error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // Get single note by ID
  static async getNoteById (req, res) {
    try {
      const noteId = parseInt(req.params.id)
      const userId = req.user.userId

      if (!noteId || noteId <= 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid note ID'
        })
      }

      const note = await database.get(
        'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?',
        [noteId, userId]
      )

      if (!note) {
        return res.status(404).json({
          success: false,
          message: 'Note not found'
        })
      }

      // Sanitize output
      const sanitizedNote = {
        id: note.id,
        title: xss(note.title),
        content: xss(note.content),
        created_at: note.created_at,
        updated_at: note.updated_at
      }

      res.json({
        success: true,
        note: sanitizedNote
      })
    } catch (error) {
      console.error('Get note error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // Create new note
  static async createNote (req, res) {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        })
      }

      const { title, content } = req.body
      const userId = req.user.userId

      // Sanitize input to prevent XSS
      const sanitizedTitle = xss(title)
      const sanitizedContent = xss(content)

      const result = await database.run(
        'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)',
        [userId, sanitizedTitle, sanitizedContent]
      )

      // Get the created note
      const newNote = await database.get(
        'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
        [result.id]
      )

      res.status(201).json({
        success: true,
        message: 'Note created successfully',
        note: newNote
      })
    } catch (error) {
      console.error('Create note error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // Update existing note
  static async updateNote (req, res) {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        })
      }

      const noteId = parseInt(req.params.id)
      const { title, content } = req.body
      const userId = req.user.userId

      if (!noteId || noteId <= 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid note ID'
        })
      }

      // Check if note exists and belongs to user
      const existingNote = await database.get(
        'SELECT id FROM notes WHERE id = ? AND user_id = ?',
        [noteId, userId]
      )

      if (!existingNote) {
        return res.status(404).json({
          success: false,
          message: 'Note not found'
        })
      }

      // Sanitize input
      const sanitizedTitle = xss(title)
      const sanitizedContent = xss(content)

      // Update note
      await database.run(
        'UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
        [sanitizedTitle, sanitizedContent, noteId, userId]
      )

      // Get updated note
      const updatedNote = await database.get(
        'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
        [noteId]
      )

      res.json({
        success: true,
        message: 'Note updated successfully',
        note: updatedNote
      })
    } catch (error) {
      console.error('Update note error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // Delete note
  static async deleteNote (req, res) {
    try {
      const noteId = parseInt(req.params.id)
      const userId = req.user.userId

      if (!noteId || noteId <= 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid note ID'
        })
      }

      // Check if note exists and belongs to user
      const existingNote = await database.get(
        'SELECT id FROM notes WHERE id = ? AND user_id = ?',
        [noteId, userId]
      )

      if (!existingNote) {
        return res.status(404).json({
          success: false,
          message: 'Note not found'
        })
      }

      // Delete note
      await database.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [
        noteId,
        userId
      ])

      res.json({
        success: true,
        message: 'Note deleted successfully'
      })
    } catch (error) {
      console.error('Delete note error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }
}

module.exports = NotesController
