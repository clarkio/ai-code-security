const express = require("express");
const router = express.Router();
const noteController = require("../controllers/noteController");
const { isAuthenticated } = require("../middleware/authMiddleware");
const { body } = require("express-validator");

router.use(isAuthenticated);

router.get("/", noteController.getNotes);

router.get("/create", noteController.getCreateNote);

router.post(
  "/create",
  [
    body("title")
      .trim()
      .isLength({ min: 1 })
      .withMessage("Title is required")
      .escape(),
    body("content")
      .trim()
      .isLength({ min: 1 })
      .withMessage("Content is required")
      .escape(),
  ],
  noteController.postCreateNote
);

router.get("/edit/:id", noteController.getEditNote);

router.post(
  "/edit/:id",
  [
    body("title")
      .trim()
      .isLength({ min: 1 })
      .withMessage("Title is required")
      .escape(),
    body("content")
      .trim()
      .isLength({ min: 1 })
      .withMessage("Content is required")
      .escape(),
  ],
  noteController.postEditNote
);

router.post("/delete/:id", noteController.postDeleteNote);

module.exports = router;
