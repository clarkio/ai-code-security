const express = require('express');
const { check, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const Note = require('../models/Note');

const router = express.Router();

// Create a note
router.post(
  '/',
  [auth, [check('title', 'Title is required').not().isEmpty(), check('body', 'Body is required').not().isEmpty()]],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { title, body } = req.body;
      const note = new Note({
        user: req.user.id,
        title,
        body
      });

      await note.save();
      res.json(note);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// Get all user's notes
router.get('/', auth, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user.id }).sort({ date: -1 });
    res.json(notes);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Delete a note
router.delete('/:id', auth, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note) return res.status(404).json({ msg: 'Note not found' });

    if (note.user.toString() !== req.user.id) return res.status(401).json({ msg: 'Not authorized' });

    await note.deleteOne({ _id: req.params.id });
    res.json({ msg: 'Note removed' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
