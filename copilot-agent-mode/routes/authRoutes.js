const express = require("express");
const { check } = require("express-validator");
const authController = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

// Signup validation
const signupValidation = [
  check("name", "Name is required").not().isEmpty().trim().escape(),
  check("email", "Please include a valid email").isEmail().normalizeEmail(),
  check("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/\d/)
    .withMessage("Password must contain a number")
    .matches(/[!@#$%^&*]/)
    .withMessage("Password must contain a special character"),
  check("passwordConfirm").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }
    return true;
  }),
];

// Auth routes
router.post("/signup", signupValidation, authController.signup);
router.post("/login", authController.login);
router.get("/logout", authController.logout);
router.get("/me", protect, authController.getMe);
router.patch(
  "/update-password",
  protect,
  [
    check("currentPassword", "Current password is required").not().isEmpty(),
    check("password")
      .isLength({ min: 8 })
      .withMessage("New password must be at least 8 characters long")
      .matches(/\d/)
      .withMessage("New password must contain a number")
      .matches(/[!@#$%^&*]/)
      .withMessage("New password must contain a special character"),
    check("passwordConfirm").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password confirmation does not match new password");
      }
      return true;
    }),
  ],
  authController.updatePassword
);

module.exports = router;
