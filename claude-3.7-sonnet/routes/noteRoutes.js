const express = require('express');
const {
  getNotes,
  getNote,
  createNote,
  updateNote,
  deleteNote,
  noteValidation
} = require('../controllers/noteController');
const { validate } = require('../middleware/validator');
const { protect } = require('../middleware/auth');

const router = express.Router();

// All routes need authentication
router.use(protect);

router
  .route('/')
  .get(getNotes)
  .post(noteValidation, validate, createNote);

router
  .route('/:id')
  .get(getNote)
  .put(noteValidation, validate, updateNote)
  .delete(deleteNote);

module.exports = router;