import { Router } from 'express';
import createError from 'http-errors';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { hashPassword, verifyPassword } from '../auth/password';
import { authRateLimit } from '../security/rateLimit';

const router = Router();

const emailSchema = z.string().email().max(254);
const passwordSchema = z.string().min(12).max(200);

router.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/notes');
  res.render('register', { title: 'Register', error: null });
});

router.post('/register', authRateLimit, async (req, res, next) => {
  try {
    if (req.session.user) return res.redirect('/notes');

    const email = emailSchema.parse(req.body.email);
    const password = passwordSchema.parse(req.body.password);

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Account already exists for that email.',
      });
    }

    const passwordHash = await hashPassword(password);
    const user = await prisma.user.create({ data: { email, passwordHash } });

    req.session.user = { id: user.id, email: user.email };
    await req.session.save();

    return res.redirect('/notes');
  } catch (err) {
    return next(err);
  }
});

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/notes');
  res.render('login', { title: 'Login', error: null });
});

router.post('/login', authRateLimit, async (req, res, next) => {
  try {
    if (req.session.user) return res.redirect('/notes');

    const email = emailSchema.parse(req.body.email);
    const password = passwordSchema.parse(req.body.password);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw createError(401);

    const ok = await verifyPassword(user.passwordHash, password);
    if (!ok) throw createError(401);

    req.session.user = { id: user.id, email: user.email };
    await req.session.save();

    return res.redirect('/notes');
  } catch (err) {
    if ((err as { status?: number }).status === 401) {
      return res.status(401).render('login', {
        title: 'Login',
        error: 'Invalid email or password.',
      });
    }
    return next(err);
  }
});

router.post('/logout', async (req, res, next) => {
  try {
    req.session.destroy();
    return res.redirect('/login');
  } catch (err) {
    return next(err);
  }
});

export default router;
