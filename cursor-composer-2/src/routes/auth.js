import { Router } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import { config } from '../config.js';
import { findUserByEmail, createUser } from '../db/index.js';
export const authRouter = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: 'Too many attempts. Try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

const loginValidators = [
  body('email').trim().isEmail().normalizeEmail().isLength({ max: 254 }),
  body('password').isString().isLength({ min: 1, max: 128 }),
];

const registerValidators = [
  body('email').trim().isEmail().normalizeEmail().isLength({ max: 254 }),
  body('password').isString().isLength({ min: 12, max: 72 }).withMessage('Password must be 12–72 characters'),
];

authRouter.get('/login', (req, res) => {
  if (req.session?.userId) {
    return res.redirect('/notes');
  }
  res.render('login', { title: 'Sign in', error: null });
});

authRouter.post('/login', authLimiter, loginValidators, async (req, res, next) => {
  try {
    if (req.session?.userId) {
      return res.redirect('/notes');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login', {
        title: 'Sign in',
        error: 'Invalid email or password.',
      });
    }
    const email = String(req.body.email || '');
    const password = String(req.body.password || '');
    const user = findUserByEmail(email);
    const ok = user && (await bcrypt.compare(password, user.password_hash));
    if (!ok) {
      return res.status(400).render('login', {
        title: 'Sign in',
        error: 'Invalid email or password.',
      });
    }
    req.session.regenerate((regenErr) => {
      if (regenErr) return next(regenErr);
      req.session.userId = user.id;
      req.session.csrfToken = null;
      res.redirect('/notes');
    });
  } catch (e) {
    next(e);
  }
});

authRouter.get('/register', (req, res) => {
  if (req.session?.userId) {
    return res.redirect('/notes');
  }
  res.render('register', { title: 'Create account', error: null });
});

authRouter.post('/register', authLimiter, registerValidators, async (req, res, next) => {
  try {
    if (req.session?.userId) {
      return res.redirect('/notes');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        title: 'Create account',
        error: 'Password must be at least 12 characters. Check your email format.',
      });
    }
    const email = String(req.body.email || '');
    const password = String(req.body.password || '');
    const passwordHash = await bcrypt.hash(password, 12);
    let userId;
    try {
      userId = createUser(email, passwordHash);
    } catch (err) {
      if (err && typeof err.message === 'string' && err.message.includes('UNIQUE constraint')) {
        return res.status(400).render('register', {
          title: 'Create account',
          error: 'Registration failed. That email may already be in use.',
        });
      }
      throw err;
    }
    req.session.regenerate((regenErr) => {
      if (regenErr) return next(regenErr);
      req.session.userId = Number(userId);
      req.session.csrfToken = null;
      res.redirect('/notes');
    });
  } catch (e) {
    next(e);
  }
});

authRouter.post('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(config.sessionCookieName, {
      path: '/',
      httpOnly: true,
      secure: config.isProd,
      sameSite: 'strict',
    });
    res.redirect('/login');
  });
});
