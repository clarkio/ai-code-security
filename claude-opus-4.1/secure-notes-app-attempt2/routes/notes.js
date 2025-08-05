const express = require("express");
const { body, param, validationResult } = require("express-validator");
const Note = require("../models/Note");
const { protect } = require("../middleware/auth");
const router = express.Router();

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map((err) => err.msg),
    });
  }
  next();
};

// All routes require authentication
router.use(protect);

// Get all notes for authenticated user
router.get("/", async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Max 100 items
    const skip = (page - 1) * limit;

    const notes = await Note.find({
      user: req.user._id,
      isDeleted: false,
    })
      .sort("-createdAt")
      .limit(limit)
      .skip(skip)
      .select("-__v");

    const total = await Note.countDocuments({
      user: req.user._id,
      isDeleted: false,
    });

    res.json({
      success: true,
      data: notes,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    next(error);
  }
});

// Get single note
router.get(
  "/:id",
  [
    param("id").isMongoId().withMessage("Invalid note ID"),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const note = await Note.findOne({
        _id: req.params.id,
        user: req.user._id,
        isDeleted: false,
      });

      if (!note) {
        return res.status(404).json({
          success: false,
          message: "Note not found",
        });
      }

      res.json({
        success: true,
        data: note,
      });
    } catch (error) {
      next(error);
    }
  }
);

// Create note
router.post(
  "/",
  [
    body("title")
      .trim()
      .isLength({ min: 1, max: 100 })
      .withMessage("Title must be between 1 and 100 characters"),
    body("content")
      .trim()
      .isLength({ min: 1, max: 5000 })
      .withMessage("Content must be between 1 and 5000 characters"),
    body("tags")
      .optional()
      .isArray({ max: 10 })
      .withMessage("Maximum 10 tags allowed"),
    body("tags.*")
      .optional()
      .isString()
      .isLength({ max: 20 })
      .withMessage("Each tag must be max 20 characters"),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const { title, content, tags } = req.body;

      const note = await Note.create({
        title,
        content,
        tags: tags || [],
        user: req.user._id,
      });

      res.status(201).json({
        success: true,
        data: note,
      });
    } catch (error) {
      next(error);
    }
  }
);

// Update note
router.put(
  "/:id",
  [
    param("id").isMongoId().withMessage("Invalid note ID"),
    body("title")
      .optional()
      .trim()
      .isLength({ min: 1, max: 100 })
      .withMessage("Title must be between 1 and 100 characters"),
    body("content")
      .optional()
      .trim()
      .isLength({ min: 1, max: 5000 })
      .withMessage("Content must be between 1 and 5000 characters"),
    body("tags")
      .optional()
      .isArray({ max: 10 })
      .withMessage("Maximum 10 tags allowed"),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const note = await Note.findOneAndUpdate(
        {
          _id: req.params.id,
          user: req.user._id,
          isDeleted: false,
        },
        req.body,
        {
          new: true,
          runValidators: true,
        }
      );

      if (!note) {
        return res.status(404).json({
          success: false,
          message: "Note not found",
        });
      }

      res.json({
        success: true,
        data: note,
      });
    } catch (error) {
      next(error);
    }
  }
);

// Soft delete note
router.delete(
  "/:id",
  [
    param("id").isMongoId().withMessage("Invalid note ID"),
    handleValidationErrors,
  ],
  async (req, res, next) => {
    try {
      const note = await Note.findOneAndUpdate(
        {
          _id: req.params.id,
          user: req.user._id,
          isDeleted: false,
        },
        { isDeleted: true },
        { new: true }
      );

      if (!note) {
        return res.status(404).json({
          success: false,
          message: "Note not found",
        });
      }

      res.json({
        success: true,
        message: "Note deleted successfully",
      });
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
