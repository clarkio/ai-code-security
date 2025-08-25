const express = require('express');
const csrf = require('csurf');
const { getDb } = require('./db');
const { registerSchema, loginSchema, noteCreateSchema, noteUpdateSchema } = require('./validators');
const { createUser, verifyLogin, getUserById } = require('./auth');
const { authRateLimiter } = require('./security');

const csrfProtection = csrf();

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) return res.redirect('/login');
    next();
}

function addLocals(req, res, next) {
    res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
    res.locals.user = req.session && req.session.userId ? getUserById(req.session.userId) : null;
    next();
}

function defineRoutes(app) {
    const router = express.Router();

    router.get('/', (req, res) => {
        if (req.session && req.session.userId) return res.redirect('/notes');
        res.render('home');
    });

    router.get('/register', csrfProtection, addLocals, (req, res) => {
        res.render('register');
    });

    router.post('/register', authRateLimiter(), csrfProtection, addLocals, async (req, res) => {
        const parsed = registerSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).render('register', { error: 'Invalid input' });
        try {
            const userId = await createUser(parsed.data.email.toLowerCase(), parsed.data.password);
            req.session.userId = userId;
            res.redirect('/notes');
        } catch (e) {
            if (e && e.code === 'EMAIL_EXISTS') {
                return res.status(400).render('register', { error: 'Email already registered' });
            }
            req.log && req.log.error(e, 'register_error');
            res.status(500).render('register', { error: 'Registration failed' });
        }
    });

    router.get('/login', csrfProtection, addLocals, (req, res) => {
        res.render('login');
    });

    router.post('/login', authRateLimiter(), csrfProtection, addLocals, async (req, res) => {
        const parsed = loginSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).render('login', { error: 'Invalid credentials' });
        const email = parsed.data.email.toLowerCase();
        const password = parsed.data.password;
        try {
            const result = await verifyLogin(email, password);
            if (!result.ok) return res.status(401).render('login', { error: 'Invalid credentials' });
            req.session.regenerate(err => {
                if (err) return res.status(500).render('login', { error: 'Session error' });
                req.session.userId = result.userId;
                res.redirect('/notes');
            });
        } catch (e) {
            req.log && req.log.error(e, 'login_error');
            res.status(500).render('login', { error: 'Login failed' });
        }
    });

    router.post('/logout', csrfProtection, requireAuth, (req, res) => {
        req.session.destroy(() => {
            res.clearCookie(req.app.get('cookieName'));
            res.redirect('/');
        });
    });

    router.get('/notes', csrfProtection, requireAuth, addLocals, (req, res) => {
        const db = getDb();
        const notes = db.prepare('SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC').all(req.session.userId);
        res.render('notes', { notes });
    });

    router.post('/notes', csrfProtection, requireAuth, (req, res) => {
        const parsed = noteCreateSchema.safeParse(req.body);
        if (!parsed.success) return res.status(400).send('Invalid note');
        const db = getDb();
        const now = Date.now();
        db.prepare('INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
            .run(req.session.userId, parsed.data.title, parsed.data.content, now, now);
        res.redirect('/notes');
    });

    router.post('/notes/:id', csrfProtection, requireAuth, (req, res) => {
        const parsed = noteUpdateSchema.safeParse({ id: req.params.id, ...req.body });
        if (!parsed.success) return res.status(400).send('Invalid note');
        const db = getDb();
        const now = Date.now();
        const info = db.prepare('UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?')
            .run(parsed.data.title, parsed.data.content, now, parsed.data.id, req.session.userId);
        if (info.changes === 0) return res.status(404).send('Not found');
        res.redirect('/notes');
    });

    router.post('/notes/:id/delete', csrfProtection, requireAuth, (req, res) => {
        const id = Number(req.params.id);
        if (!Number.isInteger(id) || id <= 0) return res.status(400).send('Invalid');
        const db = getDb();
        const info = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(id, req.session.userId);
        if (info.changes === 0) return res.status(404).send('Not found');
        res.redirect('/notes');
    });

    return router;
}

module.exports = { defineRoutes };


