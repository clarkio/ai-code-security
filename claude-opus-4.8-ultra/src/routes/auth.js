'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const userModel = require('../models/userModel');
const { registerSchema, loginSchema } = require('../validators');

const router = express.Router();

// Strict rate limit on credential endpoints to blunt brute-force and
// credential-stuffing attacks. Keyed by IP.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: undefined,
  handler: (req, res) =>
    res.status(429).render('error', {
      title: 'Too Many Requests',
      message: 'Too many attempts. Please wait a few minutes and try again.',
    }),
});

/**
 * Regenerate the session on login to prevent session fixation, then persist the
 * authenticated identity.
 */
function establishSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
    });
  });
}

router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/notes');
  res.render('register', { title: 'Register', errors: [], values: {} });
});

router.post('/register', authLimiter, async (req, res, next) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).render('register', {
        title: 'Register',
        errors: parsed.error.issues.map((i) => i.message),
        values: { username: req.body.username || '' },
      });
    }

    const { username, password } = parsed.data;

    if (userModel.usernameExists(username)) {
      return res.status(409).render('register', {
        title: 'Register',
        errors: ['That username is already taken.'],
        values: { username },
      });
    }

    const user = await userModel.createUser(username, password);
    await establishSession(req, user);
    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/notes');
  res.render('login', { title: 'Log in', errors: [], values: {} });
});

router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      // Deliberately generic: never reveal which field/credential was wrong.
      return res.status(400).render('login', {
        title: 'Log in',
        errors: ['Invalid username or password.'],
        values: { username: req.body.username || '' },
      });
    }

    const { username, password } = parsed.data;
    const user = await userModel.verifyCredentials(username, password);
    if (!user) {
      return res.status(401).render('login', {
        title: 'Log in',
        errors: ['Invalid username or password.'],
        values: { username },
      });
    }

    await establishSession(req, user);
    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

router.post('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    return res.redirect('/login');
  });
});

module.exports = router;
