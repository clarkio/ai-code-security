const express = require('express');
const {
  register,
  login,
  getMe,
  registerValidation,
  loginValidation
} = require('../controllers/authController');
const { validate } = require('../middleware/validator');
const { protect } = require('../middleware/auth');

const router = express.Router();

router.post('/register', registerValidation, validate, register);
router.post('/login', loginValidation, validate, login);
router.get('/me', protect, getMe);

module.exports = router;