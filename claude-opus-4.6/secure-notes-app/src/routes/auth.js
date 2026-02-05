const express = require('express');
const bcrypt = require('bcryptjs');
const { queries } = require('../database');
const { getErrors, registerRules, loginRules } = require('../middleware/validate');

const BCRYPT_SALT_ROUNDS = 12;

module.exports = function authRoutes(authLimiter) {
  const router = express.Router();

  // --- Registration ---
  router.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.render('register', { errors: null });
  });

  router.post('/register', authLimiter, registerRules, async (req, res) => {
    const errors = getErrors(req);
    if (errors) {
      return res.status(400).render('register', { errors });
    }

    const { email, password } = req.body;

    // Check if user already exists
    const existing = queries.getUserByEmail(email);
    if (existing) {
      return res
        .status(409)
        .render('register', { errors: ['An account with this email already exists'] });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const userId = queries.createUser(email, passwordHash);

    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).send('An unexpected error occurred');
      }
      req.session.userId = userId;
      req.session.save(() => res.redirect('/'));
    });
  });

  // --- Login ---
  router.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.render('login', { errors: null });
  });

  router.post('/login', authLimiter, loginRules, async (req, res) => {
    const errors = getErrors(req);
    if (errors) {
      return res.status(400).render('login', { errors });
    }

    const { email, password } = req.body;

    // Use constant-time message whether email is wrong or password is wrong
    // to prevent user enumeration
    const genericError = ['Invalid email or password'];

    const user = queries.getUserByEmail(email);
    if (!user) {
      // Still hash to prevent timing-based user enumeration
      await bcrypt.hash('dummy', BCRYPT_SALT_ROUNDS);
      return res.status(401).render('login', { errors: genericError });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).render('login', { errors: genericError });
    }

    // Regenerate session to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).send('An unexpected error occurred');
      }
      req.session.userId = user.id;
      req.session.save(() => res.redirect('/'));
    });
  });

  // --- Logout ---
  router.post('/logout', (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('__sid');
      res.redirect('/login');
    });
  });

  return router;
};
