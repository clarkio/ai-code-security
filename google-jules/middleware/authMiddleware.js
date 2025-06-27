const jwt = require('jsonwebtoken');
const jwtConfig = require('../config/jwt');
const User = require('../models/user'); // Optional: to fetch full user object

module.exports = function(req, res, next) {
    // Get token from header
    const authHeader = req.header('Authorization');

    // Check if not token
    if (!authHeader) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Check if token is in Bearer format
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).json({ msg: 'Token is not valid, not Bearer format' });
    }
    
    const token = parts[1];

    try {
        const decoded = jwt.verify(token, jwtConfig.secret);
        req.user = decoded.user; // Add user from payload (should contain user id)
        
        // Optional: Fetch user from DB to ensure they still exist / have up-to-date info
        // User.findUserById(req.user.id).then(user => {
        //     if (!user) return res.status(401).json({ msg: 'User not found' });
        //     req.user = user; // Replace payload with full user object if needed
        //     next();
        // }).catch(err => {
        //     console.error('Error fetching user in auth middleware:', err);
        //     return res.status(500).send('Server error');
        // });
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};
