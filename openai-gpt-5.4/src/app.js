const path = require("node:path");
const crypto = require("node:crypto");

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const pinoHttp = require("pino-http");
const { csrfSync } = require("csrf-sync");
const { z } = require("zod");

const FileStoreFactory = require("session-file-store");

const { createStore } = require("./db");
const { verifyPassword } = require("./security");

const noteSchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, "Title is required.")
    .max(120, "Title must be 120 characters or fewer."),
  content: z
    .string()
    .max(5000, "Content must be 5000 characters or fewer.")
    .refine((value) => value.trim().length > 0, "Content is required.")
    .transform((value) => value.trim()),
});

const loginSchema = z.object({
  username: z
    .string()
    .trim()
    .min(1, "Username is required.")
    .max(100, "Invalid username."),
  password: z
    .string()
    .min(1, "Password is required.")
    .max(256, "Invalid password."),
});

const idSchema = z.coerce.number().int().positive();

function createApp(config) {
  const app = express();
  const notesStore = createStore(config);
  const FileStore = FileStoreFactory(session);
  const sessionStore = new FileStore({
    path: config.sessionDir,
    reapInterval: 15 * 60,
    retries: 0,
  });

  const { generateToken, csrfSynchronisedProtection, invalidCsrfTokenError } =
    csrfSync({
      getTokenFromRequest: (req) => req.body?._csrf || req.get("x-csrf-token"),
    });

  if (config.trustProxy) {
    app.set("trust proxy", 1);
  }

  app.disable("x-powered-by");
  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "views"));

  app.use(
    pinoHttp({
      enabled: config.env !== "test",
      quietReqLogger: true,
      genReqId: (req, res) => {
        const existing = req.headers["x-request-id"];
        const requestId =
          typeof existing === "string" && existing
            ? existing
            : crypto.randomUUID();
        res.setHeader("x-request-id", requestId);
        return requestId;
      },
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "res.headers['set-cookie']",
        ],
        censor: "[Redacted]",
      },
    }),
  );

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          baseUri: ["'none'"],
          fontSrc: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          imgSrc: ["'self'", "data:"],
          objectSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          upgradeInsecureRequests: config.isProduction ? [] : null,
        },
      },
      crossOriginEmbedderPolicy: false,
      frameguard: { action: "deny" },
      referrerPolicy: { policy: "no-referrer" },
    }),
  );

  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: config.globalRateLimitMax,
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config.authRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many login attempts. Please try again later.",
    skipSuccessfulRequests: true,
  });

  app.use(
    express.static(path.join(config.rootDir, "public"), {
      immutable: config.isProduction,
      maxAge: config.isProduction ? "1d" : 0,
    }),
  );

  app.use(express.urlencoded({ extended: false, limit: config.bodyLimit }));

  app.use(
    session({
      name: config.sessionCookieName,
      secret: config.sessionSecret,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      rolling: false,
      cookie: {
        httpOnly: true,
        maxAge: config.sessionDurationMs,
        sameSite: "strict",
        secure: config.isProduction,
      },
    }),
  );

  app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.locals.csrfToken = generateToken(req);
    res.locals.currentUser = req.session.user || null;
    next();
  });

  app.use(csrfSynchronisedProtection);

  function requireAuth(req, res, next) {
    if (req.session.user) {
      return next();
    }

    return res.redirect("/login");
  }

  function renderView(res, view, input = {}) {
    return res.status(input.statusCode || 200).render(view, {
      errorMessage: null,
      formData: {},
      ...input,
    });
  }

  function parseId(value) {
    const parsed = idSchema.safeParse(value);
    return parsed.success ? parsed.data : null;
  }

  app.get("/", (req, res) => {
    if (req.session.user) {
      return res.redirect("/notes");
    }

    return res.redirect("/login");
  });

  app.get("/login", (req, res) => {
    if (req.session.user) {
      return res.redirect("/notes");
    }

    return renderView(res, "login", { title: "Sign in" });
  });

  app.post("/login", authLimiter, async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return renderView(res, "login", {
        title: "Sign in",
        statusCode: 400,
        errorMessage: parsed.error.issues[0].message,
        formData: { username: req.body.username || "" },
      });
    }

    const { username, password } = parsed.data;
    const isValidUser = username === config.adminUsername;
    const isValidPassword = verifyPassword(password, config.adminPasswordHash);

    if (!isValidUser || !isValidPassword) {
      return renderView(res, "login", {
        title: "Sign in",
        statusCode: 401,
        errorMessage: "Invalid credentials.",
        formData: { username },
      });
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => {
        if (error) {
          reject(error);
          return;
        }

        req.session.user = { username };
        resolve();
      });
    });

    return res.redirect("/notes");
  });

  app.post("/logout", requireAuth, async (req, res, next) => {
    const sessionToDestroy = req.session;

    try {
      await new Promise((resolve, reject) => {
        sessionToDestroy.destroy((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    } catch (error) {
      return next(error);
    }

    res.clearCookie(config.sessionCookieName);
    return res.redirect("/login");
  });

  app.get("/notes", requireAuth, (req, res) => {
    return renderView(res, "notes/index", {
      title: "Notes",
      notes: notesStore.listNotes(),
    });
  });

  app.post("/notes", requireAuth, (req, res) => {
    const parsed = noteSchema.safeParse(req.body);
    if (!parsed.success) {
      return renderView(res, "notes/index", {
        title: "Notes",
        notes: notesStore.listNotes(),
        statusCode: 400,
        errorMessage: parsed.error.issues[0].message,
        formData: req.body,
      });
    }

    notesStore.createNote(parsed.data);
    return res.redirect("/notes");
  });

  app.get("/notes/:id/edit", requireAuth, (req, res) => {
    const id = parseId(req.params.id);
    if (!id) {
      return renderView(res, "error", {
        title: "Invalid request",
        statusCode: 400,
        errorMessage: "Invalid note identifier.",
      });
    }

    const note = notesStore.getNoteById(id);
    if (!note) {
      return renderView(res, "error", {
        title: "Not found",
        statusCode: 404,
        errorMessage: "Note not found.",
      });
    }

    return renderView(res, "notes/edit", {
      title: "Edit note",
      note,
    });
  });

  app.post("/notes/:id", requireAuth, (req, res) => {
    const id = parseId(req.params.id);
    if (!id) {
      return renderView(res, "error", {
        title: "Invalid request",
        statusCode: 400,
        errorMessage: "Invalid note identifier.",
      });
    }

    const existingNote = notesStore.getNoteById(id);
    if (!existingNote) {
      return renderView(res, "error", {
        title: "Not found",
        statusCode: 404,
        errorMessage: "Note not found.",
      });
    }

    const parsed = noteSchema.safeParse(req.body);
    if (!parsed.success) {
      return renderView(res, "notes/edit", {
        title: "Edit note",
        note: { ...existingNote, ...req.body, id },
        statusCode: 400,
        errorMessage: parsed.error.issues[0].message,
      });
    }

    notesStore.updateNote({ id, ...parsed.data });
    return res.redirect("/notes");
  });

  app.post("/notes/:id/delete", requireAuth, (req, res) => {
    const id = parseId(req.params.id);
    if (!id) {
      return renderView(res, "error", {
        title: "Invalid request",
        statusCode: 400,
        errorMessage: "Invalid note identifier.",
      });
    }

    const existingNote = notesStore.getNoteById(id);
    if (!existingNote) {
      return renderView(res, "error", {
        title: "Not found",
        statusCode: 404,
        errorMessage: "Note not found.",
      });
    }

    notesStore.deleteNote(id);
    return res.redirect("/notes");
  });

  app.use((req, res) => {
    return renderView(res, "error", {
      title: "Not found",
      statusCode: 404,
      errorMessage: "The requested page could not be found.",
    });
  });

  app.use((error, req, res, next) => {
    if (error === invalidCsrfTokenError || error?.code === "EBADCSRFTOKEN") {
      return renderView(res, "error", {
        title: "Invalid request",
        statusCode: 403,
        errorMessage:
          "Security validation failed. Refresh the page and try again.",
      });
    }

    req.log.error({ err: error }, "Unhandled application error");

    return renderView(res, "error", {
      title: "Server error",
      statusCode: 500,
      errorMessage: config.isProduction
        ? "An unexpected error occurred."
        : error.message,
    });
  });

  return app;
}

module.exports = {
  createApp,
};
