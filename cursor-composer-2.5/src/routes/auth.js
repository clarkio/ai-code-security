import { Router } from 'express';
import bcrypt from 'bcrypt';
import {
  createUser,
  getUserByUsername,
} from '../db/database.js';
import { config } from '../config.js';
import { redirectIfAuthenticated, requireAuth } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimit.js';
import { validateBody } from '../middleware/validate.js';
import { loginSchema, registerSchema } from '../validation/schemas.js';

const router = Router();

router.get('/login', redirectIfAuthenticated, (req, res) => {
  res.render('login', { title: 'Sign in' });
});

router.get('/register', redirectIfAuthenticated, (req, res) => {
  res.render('register', { title: 'Create account' });
});

router.post(
  '/register',
  authLimiter,
  redirectIfAuthenticated,
  validateBody(registerSchema, { redirectTo: '/register' }),
  async (req, res, next) => {
    try {
      const { username, password } = req.validated;
      const normalizedUsername = username.toLowerCase();

      if (getUserByUsername(normalizedUsername)) {
        req.session.flash = { type: 'error', message: 'Username is already taken.' };
        return res.redirect('/register');
      }

      const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
      createUser(normalizedUsername, passwordHash);

      req.session.flash = {
        type: 'success',
        message: 'Account created. Please sign in.',
      };
      return res.redirect('/login');
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  '/login',
  authLimiter,
  redirectIfAuthenticated,
  validateBody(loginSchema, { redirectTo: '/login' }),
  async (req, res, next) => {
    try {
      const { username, password } = req.validated;
      const normalizedUsername = username.toLowerCase();
      const user = getUserByUsername(normalizedUsername);

      const valid =
        user &&
        (await bcrypt.compare(password, user.password_hash));

      if (!valid) {
        req.session.flash = { type: 'error', message: 'Invalid username or password.' };
        return res.redirect('/login');
      }

      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => (err ? reject(err) : resolve()));
      });

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.csrfSessionId = crypto.randomUUID();

      return res.redirect('/notes');
    } catch (err) {
      next(err);
    }
  }
);

router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.clearCookie(config.isProduction ? '__Host-csrf' : 'csrf-token', { path: '/' });
    res.redirect('/login');
  });
});

export default router;
