const express = require('express');
const { body, param, query } = require('express-validator');
const { db, generateId } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const { validate, titleValidator, contentValidator, idValidator } = require('../middleware/validation');
const { sanitizePlainText, sanitizeForStorage, detectXSS } = require('../lib/sanitizer');
const { strictLimiter } = require('../middleware/security');

const router = express.Router();

router.use(authenticate);

router.get('/', strictLimiter, [
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt()
], validate, (req, res) => {
  const page = parseInt(query('page') || 1);
  const limit = parseInt(query('limit') || 20);
  const offset = (page - 1) * limit;

  const countStmt = db.prepare('SELECT COUNT(*) as total FROM notes WHERE user_id = ?');
  const total = countStmt.get(req.user.id).total;

  const stmt = db.prepare(`
    SELECT id, title, created_at, updated_at
    FROM notes
    WHERE user_id = ?
    ORDER BY updated_at DESC
    LIMIT ? OFFSET ?
  `);
  const notes = stmt.all(req.user.id, limit, offset);

  res.json({
    notes,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
});

router.get('/:id', strictLimiter, [idValidator], validate, (req, res) => {
  const stmt = db.prepare(`
    SELECT id, title, content, created_at, updated_at
    FROM notes
    WHERE id = ? AND user_id = ?
  `);
  const note = stmt.get(req.params.id, req.user.id);

  if (!note) {
    return res.status(404).json({ error: 'Note not found' });
  }

  res.json({ note });
});

router.post('/', strictLimiter, [
  titleValidator,
  contentValidator
], validate, (req, res) => {
  const sanitizedTitle = sanitizePlainText(req.body.title);
  const sanitizedContent = sanitizeForStorage(req.body.content || '');

  if (detectXSS(sanitizedTitle) || detectXSS(sanitizedContent)) {
    return res.status(400).json({ error: 'Invalid content detected' });
  }

  const noteId = generateId();
  const stmt = db.prepare(`
    INSERT INTO notes (id, user_id, title, content)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run(noteId, req.user.id, sanitizedTitle, sanitizedContent);

  const note = db.prepare('SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?').get(noteId);

  res.status(201).json({ note });
});

router.put('/:id', strictLimiter, [
  idValidator,
  titleValidator,
  contentValidator
], validate, (req, res) => {
  const sanitizedTitle = sanitizePlainText(req.body.title);
  const sanitizedContent = sanitizeForStorage(req.body.content || '');

  if (detectXSS(sanitizedTitle) || detectXSS(sanitizedContent)) {
    return res.status(400).json({ error: 'Invalid content detected' });
  }

  const existingNote = db.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);

  if (!existingNote) {
    return res.status(404).json({ error: 'Note not found' });
  }

  const stmt = db.prepare(`
    UPDATE notes
    SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND user_id = ?
  `);

  stmt.run(sanitizedTitle, sanitizedContent, req.params.id, req.user.id);

  const note = db.prepare('SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?').get(req.params.id);

  res.json({ note });
});

router.delete('/:id', strictLimiter, [idValidator], validate, (req, res) => {
  const existingNote = db.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);

  if (!existingNote) {
    return res.status(404).json({ error: 'Note not found' });
  }

  const stmt = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
  stmt.run(req.params.id, req.user.id);

  res.json({ message: 'Note deleted successfully' });
});

module.exports = router;
