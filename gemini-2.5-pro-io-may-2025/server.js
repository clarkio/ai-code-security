// server.js
require('dotenv').config(); // Load environment variables first

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db'); // Initializes DB connection
const { generateCsrfToken, validateCsrfToken } = require('./middleware/csrfMiddleware');

const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Trust proxy for secure cookies if behind a reverse proxy (like Nginx or Heroku)
if (IS_PROD) {
    app.set('trust proxy', 1); // trust first proxy
}

// --- Middleware ---

// Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Add any CDNs if you use them, e.g. 'https://cdn.jsdelivr.net'
            styleSrc: ["'self'", "'unsafe-inline'"], // unsafe-inline only if absolutely necessary for small styles, else use files
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"], // Prevents clickjacking
            formAction: ["'self'"], // Restrict where forms can submit to
        },
    },
    hsts: { // HTTP Strict Transport Security
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true // If you plan to submit your site to HSTS preload lists
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Rate Limiting (apply to all requests, or more specifically to auth/sensitive routes)
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // limit each IP to 200 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: 'Too many requests from this IP, please try again after 15 minutes.'
});
app.use(generalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: IS_PROD ? 10 : 50, // Limit login/register attempts ( stricter in prod)
    message: 'Too many attempts from this IP, please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
});


// Body Parsers
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: false })); // For parsing application/x-www-form-urlencoded

// Session Configuration
app.use(session({
    store: new SQLiteStore({
        db: path.basename(process.env.DATABASE_URL || 'notes.db'), // Use just the filename for SQLiteStore
        dir: path.dirname(process.env.DATABASE_URL || path.join(__dirname, 'notes.db')), // Directory for the DB file
        table: 'sessions', // Table name for sessions
        concurrentDB: true // Allows for multiple connections, good for SQLite
    }),
    secret: process.env.SESSION_SECRET,
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
        secure: IS_PROD, // Require HTTPS in production
        httpOnly: true, // Prevent client-side JS access
        sameSite: 'lax', // CSRF protection: 'strict' or 'lax'. 'Lax' is a good default.
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Flash messages middleware (simple implementation)
app.use((req, res, next) => {
    res.locals.messages = req.session.flashMessages || {};
    delete req.session.flashMessages;

    req.flash = (type, message) => {
        if (!req.session.flashMessages) {
            req.session.flashMessages = {};
        }
        if (!req.session.flashMessages[type]) {
            req.session.flashMessages[type] = [];
        }
        // If message is an array, concat, else push
        if (Array.isArray(message)) {
            req.session.flashMessages[type] = req.session.flashMessages[type].concat(message);
        } else {
            req.session.flashMessages[type].push(message);
        }
    };
    next();
});


// CSRF Token Middleware (must be after session and parsers)
app.use(generateCsrfToken); // Generates token and makes it available
app.use(validateCsrfToken); // Validates token on POST/PUT/DELETE


// View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static Files
app.use(express.static(path.join(__dirname, 'public')));

// Make session user available to all templates
app.use((req, res, next) => {
    res.locals.user = req.session.username || null; // Or req.session.user object if you store more
    next();
});


// --- Routes ---
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/notes');
    } else {
        res.redirect('/auth/login');
    }
});

app.use('/auth', authLimiter, authRoutes); // Apply stricter rate limit to auth routes
app.use('/notes', notesRoutes);


// --- Error Handling ---

// 404 Not Found Handler
app.use((req, res, next) => {
    const err = new Error('Not Found');
    err.status = 404;
    // Log the 404 attempt
    console.warn(`404 Not Found: ${req.method} ${req.originalUrl} from ${req.ip}`);
    res.status(404).render('404', { // Create a views/404.ejs if you want a custom page
        title: "Page Not Found",
        message: "Sorry, the page you are looking for does not exist.",
        user: req.session.username,
        csrfToken: req.session.csrfToken, // CSRF token might be needed if 404 page has forms
        messages: {} // Ensure messages object exists
    });
});


// General Error Handler (must be last middleware)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', {
        message: err.message,
        status: err.status,
        stack: IS_PROD ? 'Stack trace hidden in production' : err.stack, // Only show stack in dev
        url: req.originalUrl,
        method: req.method,
        ip: req.ip
    });

    const statusCode = err.status || 500;
    const message = IS_PROD ? 'An unexpected error occurred. Please try again later.' : err.message;
    
    res.status(statusCode);
    res.render('error', { // Create a views/error.ejs
        title: `Error ${statusCode}`,
        message: message,
        errorDetail: IS_PROD ? '' : err.stack, // For development debugging
        user: req.session.username,
        csrfToken: req.session.csrfToken, // CSRF token might be needed if error page has forms
        messages: {} // Ensure messages object exists
    });
});

// --- Start Server ---
const server = app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on http://localhost:${PORT}`);
});

// Graceful Shutdown
process.on('SIGINT', () => {
    console.log('\nSIGINT received. Shutting down gracefully...');
    server.close(() => {
        console.log('HTTP server closed.');
        db.close((err) => {
            if (err) {
                console.error('Error closing database:', err.message);
            } else {
                console.log('Database connection closed.');
            }
            process.exit(0);
        });
    });
});

process.on('SIGTERM', () => {
    console.log('\nSIGTERM received. Shutting down gracefully...');
    server.close(() => {
        console.log('HTTP server closed.');
        db.close((err) => {
            if (err) {
                console.error('Error closing database:', err.message);
            } else {
                console.log('Database connection closed.');
            }
            process.exit(0);
        });
    });
});