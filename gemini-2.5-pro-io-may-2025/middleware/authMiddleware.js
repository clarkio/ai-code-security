// middleware/authMiddleware.js
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    req.flash('error', 'You must be logged in to view that page.');
    res.redirect('/auth/login');
}

function isGuest(req, res, next) {
    if (!req.session.userId) {
        return next();
    }
    res.redirect('/notes');
}

module.exports = { isAuthenticated, isGuest };