require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const csurf = require("csurf");
const knex = require("knex")(require("../knexfile"));
const authRoutes = require("./routes/auth");
const notesRoutes = require("./routes/notes");

const app = express();
const PORT = process.env.PORT || 3000;

// Security middlewares
app.disable("x-powered-by");
// Set secure headers carefully (CSP restricts external content)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);
// HSTS only in production
if (process.env.NODE_ENV === "production") {
  app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
}
app.use(express.json({ limit: "10kb" }));
app.use(morgan("combined"));

// Rate limiter
const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Session store and configuration (secure cookie settings)
app.set("trust proxy", process.env.TRUST_PROXY === "true");

app.use(
  session({
    store: new PgSession({
      pool: knex.client.pool, // re-use knex's pool
      tableName: "session",
    }),
    name: "sid",
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// CSRF protection for state-changing requests
app.use(csurf());

// Expose CSRF token for clients (double-submit cookie or fetch token before state-changing requests)
app.get("/api/csrf-token", (req, res) =>
  res.json({ csrfToken: req.csrfToken() })
);

// Routes
app.use("/api/auth", authRoutes(knex));
app.use("/api/notes", notesRoutes(knex));

// Basic healthcheck
app.get("/health", (req, res) => res.json({ ok: true }));

// Global error handler (no stack traces in prod)
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  console.error(err);
  res.status(500).json({ error: "Internal Server Error" });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
