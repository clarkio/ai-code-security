/**
 * Auth routes - login, register, logout
 */
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { body, validationResult } from 'express-validator';
import { createUser, getUserByUsername } from '../db/index.js';
import { requireAuth, redirectIfAuthenticated } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 12;

const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .withMessage('Username must be 3-32 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username may only contain letters, numbers, underscore, hyphen'),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters')
    .matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  body('passwordConfirm').custom((value, { req }) => {
    if (value !== req.body.password) throw new Error('Passwords do not match');
    return true;
  }),
];

const loginValidation = [
  body('username').trim().notEmpty().withMessage('Username required'),
  body('password').notEmpty().withMessage('Password required'),
];

router.get('/login', redirectIfAuthenticated, (req, res) => {
  res.render('login', { title: 'Log in', csrfToken: req.csrfToken?.() });
});

router.get('/register', redirectIfAuthenticated, (req, res) => {
  res.render('register', { title: 'Register', csrfToken: req.csrfToken?.() });
});

router.post(
  '/register',
  redirectIfAuthenticated,
  registerValidation,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        title: 'Register',
        csrfToken: req.csrfToken?.(),
        errors: errors.array(),
      });
    }

    const { username, password } = req.body;
    const existing = getUserByUsername(username);
    if (existing) {
      return res.status(400).render('register', {
        title: 'Register',
        csrfToken: req.csrfToken?.(),
        errors: [{ msg: 'Username already taken' }],
      });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    createUser(username, hash);
    res.redirect('/login');
  }
);

router.post('/login', redirectIfAuthenticated, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', {
      title: 'Log in',
      csrfToken: req.csrfToken?.(),
      errors: errors.array(),
    });
  }

  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).render('login', {
      title: 'Log in',
      csrfToken: req.csrfToken?.(),
      errors: [{ msg: 'Invalid username or password' }],
    });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect('/');
});

router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send('Logout failed');
    res.redirect('/login');
  });
});

export default router;
