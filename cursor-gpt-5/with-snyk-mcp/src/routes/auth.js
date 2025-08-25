'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { User } = require('../models/User');

const authRouter = express.Router();

const emailRule = body('email').isEmail().normalizeEmail();
const passwordRule = body('password').isLength({ min: 12, max: 128 });

authRouter.post('/register', [emailRule, passwordRule], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input', details: errors.array() });
    }
    const { email, password } = req.body;
    const existing = await User.findOne({ email }).lean();
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, passwordHash });
    return res.status(201).json({ id: user._id.toString(), email: user.email });
});

authRouter.post('/login', [emailRule, passwordRule], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input', details: errors.array() });
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ sub: user._id.toString() }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
    return res.status(200).json({ token });
});

authRouter.post('/logout', (_req, res) => res.status(200).json({ ok: true }));

module.exports = { authRouter };


