'use strict';

const express = require('express');
const bcrypt = require('bcrypt');

const config = require('../config');
const db = require('../db');
const { credentialsSchema } = require('../validators');
const { rotateToken } = require('../middleware/csrf');
const { requireGuest, requireAuth } = require('../middleware/auth');
const { loginLimiter, signupLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Pre-computed hash used to keep timing roughly constant for unknown users.
// Avoids leaking which usernames exist via response time differences.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password-placeholder', config.bcryptCost);

router.get('/login', requireGuest, (req, res) => {
  res.render('login', { title: 'Log in', error: null, username: '' });
});

router.post('/login', requireGuest, loginLimiter, async (req, res, next) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    // Don't echo password back; echo username only.
    return res.status(400).render('login', {
      title: 'Log in',
      error: 'Invalid username or password.',
      username: typeof req.body.username === 'string' ? req.body.username.slice(0, 64) : '',
    });
  }

  const { username, password } = parsed.data;

  try {
    const user = db.findUserByUsername(username);
    // Always run bcrypt to equalize timing for missing users.
    const hash = user ? user.password_hash : DUMMY_HASH;
    const ok = await bcrypt.compare(password, hash);

    if (!user || !ok) {
      return res.status(401).render('login', {
        title: 'Log in',
        error: 'Invalid username or password.',
        username,
      });
    }

    // Prevent session fixation: regenerate the session id on privilege change.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      rotateToken(req);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect('/notes');
      });
    });
  } catch (err) {
    next(err);
  }
});

router.get('/signup', requireGuest, (req, res) => {
  res.render('signup', { title: 'Sign up', error: null, username: '' });
});

router.post('/signup', requireGuest, signupLimiter, async (req, res, next) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    const fieldHint =
      firstIssue && firstIssue.path[0] === 'password'
        ? `Password must be ${config.limits.passwordMin}-${config.limits.passwordMax} characters.`
        : `Username must be ${config.limits.usernameMin}-${config.limits.usernameMax} characters and use letters, digits, "_", ".", or "-".`;
    return res.status(400).render('signup', {
      title: 'Sign up',
      error: fieldHint,
      username: typeof req.body.username === 'string' ? req.body.username.slice(0, 64) : '',
    });
  }

  const { username, password } = parsed.data;

  try {
    const passwordHash = await bcrypt.hash(password, config.bcryptCost);
    let user;
    try {
      user = db.createUser(username, passwordHash);
    } catch (e) {
      // SQLITE_CONSTRAINT_UNIQUE on username collision.
      if (e && typeof e.code === 'string' && e.code.startsWith('SQLITE_CONSTRAINT')) {
        return res.status(409).render('signup', {
          title: 'Sign up',
          error: 'That username is taken.',
          username,
        });
      }
      throw e;
    }

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      rotateToken(req);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect('/notes');
      });
    });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', requireAuth, (req, res, next) => {
  // Destroy server-side session and clear the cookie.
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(config.session.name, {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.isProd,
      path: '/',
    });
    res.redirect('/login');
  });
});

module.exports = router;
