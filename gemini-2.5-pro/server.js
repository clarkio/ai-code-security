require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const csrf = require('csurf');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const path = require('path');
const morgan = require('morgan');

const noteRoutes = require('./routes/notes'); // We will create this next

const app = express();

// Basic Security Setup
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'"], // Allow scripts only from self
            "style-src": ["'self'", "'unsafe-inline'"], // Allow styles from self and inline (adjust if needed)
            "img-src": ["'self'", "data:"],
        },
    },
    crossOriginEmbedderPolicy: false, // Adjust if needed based on embedded content
}));

// Rate Limiting (adjust points/duration as needed)
const rateLimiter = new RateLimiterMemory({
    points: 10, // 10 requests
    duration: 1, // per 1 second by IP
});

const rateLimitMiddleware = (req, res, next) => {
    rateLimiter.consume(req.ip)
        .then(() => {
            next();
        })
        .catch(() => {
            res.status(429).send('Too Many Requests');
        });
};
app.use(rateLimitMiddleware);


// Environment Variables Check
if (!process.env.MONGODB_URI || !process.env.SESSION_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI and SESSION_SECRET must be defined in .env file.");
    process.exit(1);
}

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => {
        console.error('MongoDB Connection Error:', err);
        process.exit(1); // Exit if cannot connect to DB
    });

// View Engine Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(morgan('dev')); // Logger - use 'combined' in production for more detail
app.use(express.json()); // Body parser for JSON
app.use(express.urlencoded({ extended: true })); // Body parser for URL-encoded forms
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// Session Configuration
const sessionConfig = {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Set to false for security, only save sessions when modified
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions' // Optional: name of the sessions collection
    }),
    cookie: {
        httpOnly: true, // Prevent client-side JS from accessing the cookie
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (requires HTTPS)
        maxAge: 1000 * 60 * 60 * 24 // Cookie expiry (e.g., 1 day)
        // sameSite: 'strict' // Consider adding 'strict' or 'lax' for further CSRF protection
    }
};

// Trust proxy headers if behind a reverse proxy (like Nginx, Heroku)
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // trust first proxy
    // sessionConfig.cookie.secure = true; // Already set above based on NODE_ENV
}

app.use(session(sessionConfig));

// CSRF Protection Setup
// Must be after session middleware and body parsers
const csrfProtection = csrf();
app.use(csrfProtection);

// Middleware to make CSRF token available to all views
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});


// --- Routes ---
app.use('/', noteRoutes); // Mount the notes routes


// --- Error Handling ---

// 404 Handler
app.use((req, res, next) => {
    res.status(404).render('error', {
        title: 'Page Not Found',
        message: 'Sorry, the page you are looking for does not exist.'
    });
});

// General Error Handler (Must be after CSRF)
// Specifically handle CSRF errors
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        console.warn('CSRF Token Error:', err);
        // Handle CSRF token errors here
        res.status(403).render('error', {
            title: 'Invalid Request',
            message: 'Form submission timed out or was invalid. Please try again.'
        });
    } else {
        // Pass other errors down
        next(err);
    }
});


// General Error Handler (Catch-all)
// IMPORTANT: Keep this last
app.use((err, req, res, next) => {
    console.error(err.stack); // Log the full error stack trace for debugging

    // Set locals, only providing error details in development
    res.locals.message = err.message;
    res.locals.error = process.env.NODE_ENV === 'development' ? err : {};

    // Render the error page
    res.status(err.status || 500);
    res.render('error', { // We need to create views/error.ejs
        title: 'Server Error',
        message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred.' : err.message
    });
});


// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
    console.log(`CSRF Protection Enabled.`);
    console.log(`Helmet Security Headers Enabled.`);
}); 