const express = require("express");
const { check } = require("express-validator");
const noteController = require("../controllers/noteController");
const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

// Protect all routes in this router
router.use(protect);

// Note validation rules
const noteValidation = [
  check("title")
    .not()
    .isEmpty()
    .withMessage("Title is required")
    .trim()
    .isLength({ max: 100 })
    .withMessage("Title cannot exceed 100 characters")
    .escape(),
  check("content")
    .not()
    .isEmpty()
    .withMessage("Content is required")
    .trim()
    .isLength({ max: 10000 })
    .withMessage("Content cannot exceed 10,000 characters")
    .escape(),
];

// Note routes
router
  .route("/")
  .get(noteController.getNotes)
  .post(noteValidation, noteController.createNote);

router
  .route("/:id")
  .get(noteController.getNote)
  .put(noteValidation, noteController.updateNote)
  .delete(noteController.deleteNote);

module.exports = router;
