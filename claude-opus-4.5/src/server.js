/**
 * Express Server - Secure Configuration
 * Main application entry point with defense-in-depth security
 */

const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");

const config = require("./config");
const logger = require("./config/logger");
const {
  helmetConfig,
  corsConfig,
  generalRateLimiter,
  hppConfig,
  validateSecurityHeaders,
} = require("./middleware/security");
const { notFoundHandler, errorHandler } = require("./middleware/errorHandler");

// Routes
const authRoutes = require("./routes/auth");
const notesRoutes = require("./routes/notes");

// Initialize Express
const app = express();

// Trust proxy (required for rate limiting behind reverse proxy)
// Set to 1 for single proxy, or configure based on your infrastructure
if (config.env === "production") {
  app.set("trust proxy", 1);
}

// ============================================
// SECURITY MIDDLEWARE (Order matters!)
// ============================================

// 1. Security headers (Helmet)
app.use(helmetConfig);

// 2. CORS protection
app.use(corsConfig);

// 3. Rate limiting
app.use(generalRateLimiter);

// 4. Cookie parser (secure cookies)
app.use(cookieParser());

// 5. Body parsing with size limits
app.use(
  express.json({
    limit: "10kb", // Prevent large payload attacks
    strict: true, // Only accept arrays and objects
  })
);
app.use(
  express.urlencoded({
    extended: false, // Use simple query parser
    limit: "10kb",
  })
);

// 6. HTTP Parameter Pollution protection
app.use(hppConfig);

// 7. Custom security header validation
app.use(validateSecurityHeaders);

// ============================================
// STATIC FILES (with security)
// ============================================

// Serve static files with security headers
app.use(
  express.static(path.join(__dirname, "public"), {
    dotfiles: "deny", // Don't serve dotfiles
    index: "index.html",
    maxAge: config.env === "production" ? "1d" : 0,
  })
);

// ============================================
// API ROUTES
// ============================================

// Health check endpoint (for load balancers)
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/notes", notesRoutes);

// Serve SPA for all other routes
app.get("*", (req, res, next) => {
  // Only serve index.html for non-API routes
  if (req.path.startsWith("/api")) {
    return next();
  }
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// ============================================
// SERVER STARTUP
// ============================================

const server = app.listen(config.port, config.host, () => {
  logger.info(`🚀 Server running in ${config.env} mode`);
  logger.info(`📍 Listening on http://${config.host}:${config.port}`);

  if (config.env === "development") {
    logger.warn(
      "⚠️  Running in development mode - not suitable for production!"
    );
  }
});

// Graceful shutdown
function gracefulShutdown(signal) {
  logger.info(`${signal} received, shutting down gracefully...`);

  server.close(() => {
    logger.info("HTTP server closed");
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled rejection at:", promise, "reason:", reason);
});

module.exports = app; // For testing
