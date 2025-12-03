const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const csurf = require("csurf");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const path = require("path");
const dotenv = require("dotenv");
const SQLiteStore = require("connect-sqlite3")(session);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security: Set various HTTP headers
app.use(helmet());

// Security: Rate limiting to prevent brute-force/DoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
});
app.use(limiter);

// Security: CORS configuration
// In a real production app, you should whitelist specific origins.
app.use(
  cors({
    origin: false, // Disable CORS for this server-side rendered app, or set to specific domain
  })
);

// Logging
app.use(morgan("combined"));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security: Session management
// Use a secure session store (SQLite in this case, Redis is better for high load)
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: "./" }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
      httpOnly: true, // Prevent client-side JS from accessing the cookie
      sameSite: "strict", // CSRF protection
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// View engine setup
app.set("views", path.join(__dirname, "src/views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "src/public")));

// Security: CSRF protection
// Must be after session and cookie-parser
// We will apply this to all routes, but we might need to exclude APIs if we had them (but we don't)
const csrfProtection = csurf({ cookie: false }); // Use session for storage
app.use(csrfProtection);

// Middleware to pass CSRF token to all views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.user = req.session.user || null;
  next();
});

// Routes
const authRoutes = require("./src/routes/authRoutes");
const noteRoutes = require("./src/routes/noteRoutes");

app.use("/", authRoutes);
app.use("/notes", noteRoutes);

app.get("/", (req, res) => {
  res.render("index", { title: "Home" });
});

// Error handling
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    // handle CSRF token errors here
    res.status(403);
    res.send("Form has been tampered with.");
    return;
  }

  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
