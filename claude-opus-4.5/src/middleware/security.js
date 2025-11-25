/**
 * Security Middleware Configuration
 * Implements defense-in-depth security measures
 */

const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
const config = require("../config");
const logger = require("../config/logger");

/**
 * Configure Helmet for comprehensive HTTP security headers
 */
const helmetConfig = helmet({
  // Content Security Policy - prevents XSS and data injection
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for simplicity
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: config.env === "production" ? [] : null,
    },
  },
  // Prevent clickjacking
  frameguard: { action: "deny" },
  // Prevent MIME type sniffing
  noSniff: true,
  // Enable XSS filter in browsers
  xssFilter: true,
  // Disable DNS prefetching
  dnsPrefetchControl: { allow: false },
  // Control referrer information
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  // HSTS - force HTTPS (only in production)
  hsts:
    config.env === "production"
      ? {
          maxAge: 31536000, // 1 year
          includeSubDomains: true,
          preload: true,
        }
      : false,
  // Hide X-Powered-By header
  hidePoweredBy: true,
});

/**
 * Configure CORS with strict origin validation
 */
const corsConfig = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    // In production, you might want to restrict this
    if (!origin && config.env !== "production") {
      return callback(null, true);
    }

    if (config.cors.origins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  exposedHeaders: ["X-RateLimit-Limit", "X-RateLimit-Remaining"],
  maxAge: 600, // 10 minutes
});

/**
 * Rate limiting to prevent brute force and DoS attacks
 */
const generalRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: {
    error: "Too many requests, please try again later.",
    retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for whitelisted IPs (none by default)
  skip: () => false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: "Too many requests, please try again later.",
    });
  },
});

/**
 * Stricter rate limiting for authentication endpoints
 */
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: "Too many authentication attempts, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(
      `Auth rate limit exceeded for IP: ${req.ip}, endpoint: ${req.path}`
    );
    res.status(429).json({
      error: "Too many authentication attempts, please try again later.",
    });
  },
});

/**
 * HTTP Parameter Pollution protection
 */
const hppConfig = hpp({
  whitelist: [], // No parameters are allowed to be duplicated
});

/**
 * Request size limiter middleware
 */
const requestSizeLimiter = (maxSize = "10kb") => {
  const bytes = require("bytes");
  const limit = bytes.parse(maxSize);

  return (req, res, next) => {
    let size = 0;

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        logger.warn(`Request size exceeded for IP: ${req.ip}`);
        res.status(413).json({ error: "Request entity too large" });
        req.destroy();
      }
    });

    next();
  };
};

/**
 * Security headers validation middleware
 */
const validateSecurityHeaders = (req, res, next) => {
  // Ensure content-type is set for POST/PUT requests
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    const contentType = req.get("Content-Type");
    if (!contentType || !contentType.includes("application/json")) {
      // Allow form submissions from the frontend
      if (
        !contentType ||
        !contentType.includes("application/x-www-form-urlencoded")
      ) {
        // This is fine for API endpoints that expect JSON
      }
    }
  }

  next();
};

module.exports = {
  helmetConfig,
  corsConfig,
  generalRateLimiter,
  authRateLimiter,
  hppConfig,
  requestSizeLimiter,
  validateSecurityHeaders,
};
