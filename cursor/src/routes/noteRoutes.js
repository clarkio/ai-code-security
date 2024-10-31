const express = require('express');
const Note = require('../models/Note');
const auth = require('../middleware/auth');
const router = express.Router();

// Create a note
router.post('/', auth, async (req, res) => {
    const { title, content } = req.body;
    const note = new Note({ title, content, userId: req.user._id });
    await note.save();
    res.status(201).send(note);
});

// Update a note
router.put('/:id', auth, async (req, res) => {
    const { title, content } = req.body;
    const note = await Note.findByIdAndUpdate(req.params.id, { title, content }, { new: true });
    res.json(note);
});

// Get all notes
router.get('/', auth, async (req, res) => {
    const notes = await Note.find({ userId: req.user._id });
    res.send(notes);
});

// Delete a note
router.delete('/:id', auth, async (req, res) => {
    await Note.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

module.exports = router;