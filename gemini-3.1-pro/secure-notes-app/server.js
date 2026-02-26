const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const { z } = require('zod');
const { initDB, getNotes, createNote, updateNote, deleteNote } = require('./database');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. SECURITY MIDDLEWARES
// ==========================================

// Helmet helps secure Express apps by setting various HTTP headers.
// We configure a strict Content Security Policy (CSP) to prevent XSS.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for simplicity, but strictly no unsafe-inline scripts
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: "deny" }, // Prevent Clickjacking
    hidePoweredBy: true, // Don't advertise we use Express
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // Enforce HTTPS (if behind proxy)
    ieNoOpen: true,
    noSniff: true, // Prevent MIME-sniffing
    referrerPolicy: { policy: "no-referrer" },
    xssFilter: true
}));

// CORS configuration - only allow requests from the same origin
app.use(cors({
    origin: 'http://localhost:3000', // Adjust this when deploying to actual domain
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type'],
    credentials: true
}));

// Rate Limiting to prevent Brute Force & basic DoS
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// Specific stricter rate limit for API endpoints
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // limit each IP to 30 requests per minute for API
    message: { error: 'Too many API requests, please slow down.' }
});

// Middleware to parse JSON bodies, strictly limited to 10kb to prevent payload starvation DoS
app.use(express.json({ limit: '10kb' }));

// Middleware to protect against HTTP Parameter Pollution attacks
app.use(hpp());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


// ==========================================
// 2. INPUT VALIDATION SCHEMAS (ZOD)
// ==========================================
const noteSchema = z.object({
    content: z.string()
        .min(1, 'Note content cannot be empty')
        .max(1000, 'Note content is too long (max 1000 chars)') // Hard limit against huge payloads
});

const idSchema = z.object({
    id: z.string().regex(/^\d+$/, 'ID must be a numeric string')
});


// ==========================================
// 3. API ROUTES
// ==========================================

// Get all notes
app.get('/api/notes', apiLimiter, async (req, res, next) => {
    try {
        const notes = await getNotes();
        res.json(notes);
    } catch (err) {
        next(err);
    }
});

// Create a new note
app.post('/api/notes', apiLimiter, async (req, res, next) => {
    try {
        // Strict input validation
        const validatedData = noteSchema.parse(req.body);

        const newNote = await createNote(validatedData.content);
        res.status(201).json(newNote);
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: 'Validation Error', details: err.errors });
        }
        next(err);
    }
});

// Update a note
app.put('/api/notes/:id', apiLimiter, async (req, res, next) => {
    try {
        // Validate both ID and Body
        const { id } = idSchema.parse(req.params);
        const validatedData = noteSchema.parse(req.body);

        const updatedNote = await updateNote(parseInt(id, 10), validatedData.content);
        if (!updatedNote) {
            return res.status(404).json({ error: 'Note not found' });
        }
        res.json(updatedNote);
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: 'Validation Error', details: err.errors });
        }
        next(err);
    }
});

// Delete a note
app.delete('/api/notes/:id', apiLimiter, async (req, res, next) => {
    try {
        const { id } = idSchema.parse(req.params);
        const deleted = await deleteNote(parseInt(id, 10));

        if (!deleted) {
            return res.status(404).json({ error: 'Note not found' });
        }
        res.status(204).send(); // No content
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: 'Validation Error', details: err.errors });
        }
        next(err);
    }
});

// ==========================================
// 4. ERROR HANDLING
// ==========================================
// Generic error handler that never leaks stack traces to the client
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err); // Log internally
    res.status(500).json({ error: 'Internal Server Error' }); // Generic message to client
});

// ==========================================
// 5. SERVER INITIALIZATION
// ==========================================
async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log(`Server running securely on http://localhost:${PORT}`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();
