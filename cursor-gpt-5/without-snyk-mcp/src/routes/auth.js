import express from 'express';
import { buildRateLimiter } from '../security.js';
import { usernameSchema, passwordSchema } from '../schema.js';
import { createUser, verifyUserPassword } from '../db.js';

const router = express.Router();

export const authLimiter = buildRateLimiter({ windowMs: 10 * 60 * 1000, max: 100 });
const sensitiveLimiter = buildRateLimiter({ windowMs: 10 * 60 * 1000, max: 20 });

router.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/notes');
    res.render('login');
});

router.post('/login', sensitiveLimiter, async (req, res) => {
    try {
        const username = usernameSchema.parse(String(req.body.username || ''));
        const password = passwordSchema.parse(String(req.body.password || ''));
        const user = await verifyUserPassword(username, password);
        if (!user) {
            return res.status(400).render('login', { error: 'Invalid credentials' });
        }
        req.session.regenerate((err) => {
            if (err) return res.status(500).render('error', { message: 'Session error' });
            req.session.userId = user.id;
            req.session.save(() => res.redirect('/notes'));
        });
    } catch (e) {
        return res.status(400).render('login', { error: 'Invalid input' });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('sid');
        res.redirect('/');
    });
});

router.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/notes');
    res.render('register');
});

router.post('/register', sensitiveLimiter, async (req, res) => {
    try {
        const username = usernameSchema.parse(String(req.body.username || ''));
        const password = passwordSchema.parse(String(req.body.password || ''));
        const id = await createUser({ username, password });
        req.session.regenerate((err) => {
            if (err) return res.status(500).render('error', { message: 'Session error' });
            req.session.userId = id;
            req.session.save(() => res.redirect('/notes'));
        });
    } catch (err) {
        const message = String(err?.message || 'Registration failed');
        const isUniqueViolation = /UNIQUE constraint failed: users\.username/.test(message);
        return res.status(400).render('register', { error: isUniqueViolation ? 'Username is taken' : 'Invalid input' });
    }
});

export default router;


