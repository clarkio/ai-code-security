const express = require('express');
const router = express.Router();
const { csrfProtection } = require('../middleware/security');
const { isAuthenticated } = require('../middleware/auth');

// Get CSRF token (authenticated users only)
router.get('/token', isAuthenticated, csrfProtection, (req, res) => {
  res.json({
    success: true,
    csrfToken: req.csrfToken(),
  });
});

module.exports = router;