import { getUserById } from '../db.js';

export function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/auth/login');
    }
    next();
}

export function attachUserToLocals(req, res, next) {
    if (req.session && req.session.userId) {
        const user = getUserById(req.session.userId);
        if (user) {
            res.locals.user = user;
        }
    }
    next();
}


