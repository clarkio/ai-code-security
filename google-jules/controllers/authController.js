const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const jwtConfig = require('../config/jwt');

exports.register = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
        let user = await User.findUserByEmail(email);
        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists with this email' }] });
        }

        user = await User.findUserByUsername(username);
        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists with this username' }] });
        }

        const newUser = await User.createUser(username, email, password);

        // Optionally, sign a JWT token and return it directly
        const payload = { user: { id: newUser.id } };
        jwt.sign(
            payload,
            jwtConfig.secret,
            { expiresIn: jwtConfig.expiresIn },
            (err, token) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Server error');
                }
                res.status(201).json({ token, message: 'User registered successfully' });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
        // next(err); // Pass error to global error handler
    }
};

exports.login = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findUserByEmail(email);
        if (!user) {
            return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' }] });
        }

        const payload = { user: { id: user.id } };

        jwt.sign(
            payload,
            jwtConfig.secret,
            { expiresIn: jwtConfig.expiresIn },
            (err, token) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Server error');
                }
                res.json({ token });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
        // next(err); // Pass error to global error handler
    }
};
