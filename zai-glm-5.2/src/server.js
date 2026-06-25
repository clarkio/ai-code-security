"use strict";

/**
 * Secure Notes App — main server.
 *
 * Security layers applied (in order of the middleware stack):
 *  1. Trust proxy (configurable) — correct client IP behind reverse proxy
 *  2. Helmet — secure HTTP headers + strict CSP
 *  3. HPP — HTTP parameter pollution protection
 *  4. Mongo sanitize — query injection defense (defense in depth)
 *  5. Compression (after security headers)
 *  6. Body parsers with strict size limits (DoS protection)
 *  7. Session — HttpOnly, Secure, SameSite=Strict cookies
 *  8. CSRF — token verification on state-changing requests
 *  9. attachUser — load current user from session
 * 10. Rate limiting — global + per-endpoint
 * 11. Routes — auth + ownership checks
 * 12. Error handler — no internal leak in production
 */

const path = require("path");
const express = require("express");
const compression = require("compression");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");

const config = require("./config/env");
const security = require("./config/security");
const { attachUser } = require("./middleware/auth");
const { csrfMiddleware } = require("./middleware/csrf");
const { notFound, errorHandler } = require("./middleware/errorHandler");

const pagesRouter = require("./routes/pages");
const authRouter = require("./routes/auth");
const notesRouter = require("./routes/notes");

const app = express();

// --- View engine (EJS auto-escapes with <%= %>) ---
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Trust proxy (set TRUST_PROXY correctly if behind nginx/load balancer) ---
if (config.trustProxy > 0) {
  app.set("trust proxy", config.trustProxy);
}

// --- Security headers (apply FIRST, before any response is sent) ---
app.use(security.helmet);
app.use(security.hpp);
app.use(security.mongoSanitize);

// --- Compression ---
app.use(compression());

// --- Request logging (combined format in prod, dev in dev) ---
app.use(
  morgan(config.isProduction ? "combined" : "dev", {
    skip: (req, res) => config.isProduction && res.statusCode < 400,
  }),
);

// --- Body parsers with strict size limits (prevent oversized payload DoS) ---
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
// cookie-parser needs the secret to verify signed cookies (used for CSRF token)
app.use(cookieParser(config.sessionSecret));

// --- Session ---
// SECURITY: cookie is HttpOnly (no JS access), Secure (HTTPS only in prod),
// SameSite=Strict (CSRF mitigation), and signed with the session secret.
const sessionConfig = {
  name: "sid", // don't use the default 'connect.sid' to avoid fingerprinting
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: config.isProduction, // require HTTPS in production
    sameSite: "strict",
    maxAge: 30 * 60 * 1000, // 30 minutes
    path: "/",
  },
};

// Use Redis for session storage in production if configured
if (config.isProduction && config.redisUrl) {
  const RedisStore = require("connect-redis")(session);
  const { createClient } = require("redis");
  const redisClient = createClient({ url: config.redisUrl });
  redisClient.connect().catch(console.error);
  sessionConfig.store = new RedisStore({ client: redisClient });
}

app.use(session(sessionConfig));

// --- CSRF protection (after session so it can read/write session token) ---
app.use(csrfMiddleware);

// --- Attach current user to every request ---
app.use(attachUser);

// --- Static files (served with correct headers via helmet) ---
app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: config.isProduction ? "1d" : 0,
    etag: true,
  }),
);

// --- Global rate limiter on API routes ---
app.use("/api", security.apiLimiter);

// --- Routes ---
app.use("/", pagesRouter);
app.use("/api/auth", authRouter);
app.use("/api/notes", notesRouter);

// --- 404 & error handlers (last) ---
app.use(notFound);
app.use(errorHandler);

// --- Start server ---
const server = app.listen(config.port, () => {
  console.log(
    `[secure-notes] running in ${config.nodeEnv} mode on port ${config.port}`,
  );
});

// --- Graceful shutdown ---
function shutdown(signal) {
  console.log(`\n[secure-notes] ${signal} received, shutting down...`);
  server.close(() => {
    const { closeDb } = require("./db/database");
    closeDb();
    console.log("[secure-notes] closed.");
    process.exit(0);
  });
  // Force exit after 10s if hanging
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// Catch unhandled errors so the process doesn't crash silently
process.on("unhandledRejection", (reason) => {
  console.error("[secure-notes] Unhandled rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[secure-notes] Uncaught exception:", err);
  shutdown("uncaughtException");
});

module.exports = app;
