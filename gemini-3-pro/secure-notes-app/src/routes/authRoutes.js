const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { body } = require("express-validator");

router.get("/register", authController.getRegister);

router.post(
  "/register",
  [
    body("username")
      .trim()
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long")
      .isAlphanumeric()
      .withMessage("Username must contain only letters and numbers")
      .escape(), // Sanitize
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long")
      .matches(/\d/)
      .withMessage("Password must contain a number")
      .matches(/[A-Z]/)
      .withMessage("Password must contain an uppercase letter")
      .trim(), // Sanitize (though usually we don't trim passwords, but for this simple app it's safer to avoid trailing spaces confusion)
  ],
  authController.postRegister
);

router.get("/login", authController.getLogin);

router.post(
  "/login",
  [body("username").trim().escape(), body("password").trim()],
  authController.postLogin
);

router.post("/logout", authController.postLogout);

module.exports = router;
