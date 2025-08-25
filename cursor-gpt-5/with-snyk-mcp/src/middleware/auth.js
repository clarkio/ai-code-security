'use strict';

const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
    try {
        const auth = req.headers['authorization'] || '';
        const parts = auth.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Unauthorized' });
        const token = parts[1];
        const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
        req.user = { userId: payload.sub };
        return next();
    } catch (e) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
}

module.exports = { requireAuth };


