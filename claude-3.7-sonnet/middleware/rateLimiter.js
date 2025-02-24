const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_TIME * 60 * 1000, // default: 15 minutes
  max: process.env.RATE_LIMIT_MAX, // default: 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later'
  }
});

module.exports = limiter;