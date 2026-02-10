import path from "node:path";
import { fileURLToPath } from "node:url";
import compression from "compression";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import { basicAuth } from "./auth.js";
import { config } from "./config.js";
import { notesRouter } from "./routes/notes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "..", "public");

export const app = express();

app.disable("x-powered-by");
app.set("trust proxy", config.trustProxy);

app.use((req, res, next) => {
  const host = req.get("host")?.trim().toLowerCase();
  if (!host || host !== config.publicHost) {
    return res.status(400).json({ error: "Invalid Host header" });
  }
  return next();
});

if (config.requireHttps) {
  app.use((req, res, next) => {
    if (req.secure) {
      return next();
    }
    return res.status(400).json({ error: "HTTPS is required" });
  });
}

app.use(
  helmet({
    referrerPolicy: { policy: "no-referrer" },
    hsts: config.requireHttps
      ? {
          maxAge: 15552000,
          includeSubDomains: true,
          preload: true,
        }
      : false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
      },
    },
  }),
);

app.use(
  rateLimit({
    windowMs: config.rateLimitWindowMs,
    limit: config.rateLimitMax,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  }),
);

app.use(hpp());
app.use(compression());
app.use(
  express.json({
    limit: `${config.maxBodyKb}kb`,
    strict: true,
    type: ["application/json"],
  }),
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use((req, res, next) => {
  if (req.path === "/health") {
    return next();
  }
  return basicAuth(req, res, next);
});

app.use((req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return next();
  }

  const origin = req.get("origin");
  if (!origin) {
    return next();
  }

  if (origin !== config.publicOrigin) {
    return res.status(403).json({ error: "Cross-site request blocked" });
  }

  return next();
});

app.use("/api/notes", notesRouter);

app.use(
  express.static(publicDir, {
    index: "index.html",
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-store");
      } else {
        res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      }
    },
  }),
);

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "Not found" });
  }
  return res.status(404).send("Not found");
});

app.use((err, _req, res, _next) => {
  if (err?.type === "entity.too.large") {
    return res.status(413).json({ error: "Payload too large" });
  }
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ error: "Invalid JSON body" });
  }
  console.error("Unhandled error:", err);
  return res.status(500).json({ error: "Internal server error" });
});
