// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { isGuest, isAuthenticated } = require('../middleware/authMiddleware');
const router = express.Router();

const saltRounds = 12; // Increased salt rounds for better security

// Registration Page
router.get('/register', isGuest, (req, res) => {
    res.render('register', { title: 'Register', errors: [], old: {} });
});

// Handle Registration
router.post('/register', isGuest, [
    body('username')
        .trim()
        .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters.')
        .isAlphanumeric().withMessage('Username must be alphanumeric.')
        .escape(), // Escape to prevent XSS if reflected
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
        .matches(/\d/).withMessage('Password must contain a number.')
        .matches(/[a-z]/).withMessage('Password must contain a lowercase letter.')
        .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter.')
        .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain a special character.'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match.');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('register', {
            title: 'Register',
            errors: errors.array(),
            old: req.body
        });
    }

    const { username, password } = req.body;

    try {
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).render('register', {
                title: 'Register',
                errors: [{ msg: 'Username already taken.' }],
                old: req.body
            });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
            if (err) {
                console.error('Registration DB error:', err.message);
                req.flash('error', 'Registration failed. Please try again.');
                return res.redirect('/auth/register');
            }
            req.flash('success', 'Registration successful! Please log in.');
            res.redirect('/auth/login');
        });
    } catch (err) {
        console.error('Registration error:', err);
        req.flash('error', 'An unexpected error occurred during registration.');
        res.status(500).redirect('/auth/register');
    }
});

// Login Page
router.get('/login', isGuest, (req, res) => {
    res.render('login', { title: 'Login', errors: [], old: {} });
});

// Handle Login
router.post('/login', isGuest, [
    body('username').trim().notEmpty().withMessage('Username is required.').escape(),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('login', {
            title: 'Login',
            errors: errors.array(),
            old: req.body
        });
    }

    const { username, password } = req.body;
    try {
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                console.error('Login DB error:', err.message);
                req.flash('error', 'Login failed. Please try again.');
                return res.redirect('/auth/login');
            }
            if (!user) {
                req.flash('error', 'Invalid username or password.');
                return res.redirect('/auth/login');
            }

            const match = await bcrypt.compare(password, user.password);
            if (match) {
                // Regenerate session on login to prevent session fixation
                req.session.regenerate((err) => {
                    if (err) {
                        console.error('Session regeneration error:', err);
                        req.flash('error', 'Login failed. Please try again.');
                        return res.redirect('/auth/login');
                    }
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.flash('success', 'Logged in successfully!');
                    res.redirect('/notes');
                });
            } else {
                req.flash('error', 'Invalid username or password.');
                res.redirect('/auth/login');
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        req.flash('error', 'An unexpected error occurred during login.');
        res.status(500).redirect('/auth/login');
    }
});

// Handle Logout
router.post('/logout', isAuthenticated, (req, res, next) => { // Changed to POST
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            req.flash('error', 'Failed to log out.');
            return next(err); // Pass error to error handler
        }
        res.clearCookie('connect.sid'); // Ensure cookie is cleared
        req.flash('success', 'Logged out successfully.');
        res.redirect('/auth/login');
    });
});


module.exports = router;