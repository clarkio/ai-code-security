import 'dotenv/config';
import path from 'path';
import fs from 'fs';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';
import rateLimit from 'express-rate-limit';
import csurf from 'csurf';
import methodOverride from 'method-override';

import { getHelmetConfig, getCspDirectives, buildRateLimiter } from './security.js';
import { attachUserToLocals, requireAuth } from './middleware/auth.js';
import authRouter, { authLimiter } from './routes/auth.js';
import notesRouter from './routes/notes.js';
import expressLayouts from 'express-ejs-layouts';

const __dirname = path.dirname(new URL(import.meta.url).pathname);

// Ensure data directory exists
const dataDir = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const app = express();

// Trust proxy if behind a reverse proxy (e.g., Nginx)
const TRUST_PROXY = (process.env.TRUST_PROXY || 'false').toLowerCase() === 'true';
if (TRUST_PROXY) {
    app.set('trust proxy', 1);
}

// Basic app hardening
app.disable('x-powered-by');

// Logging
if (process.env.NODE_ENV !== 'production') {
    app.use(morgan('dev'));
}

// Security headers
app.use(helmet(getHelmetConfig()));
// Global basic rate limit
app.use(buildRateLimiter({ windowMs: 60 * 1000, max: 300 }));

// Compression
app.use(compression());

// Body parsing with conservative limits
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// Method override for HTML forms
app.use(methodOverride((req) => {
    if (req.body && typeof req.body === 'object' && '_method' in req.body) {
        const method = req.body._method;
        delete req.body._method;
        return method;
    }
    return undefined;
}));

// Sessions
const SQLiteStore = connectSqlite3(session);
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    console.error('SESSION_SECRET must be set to a long random string (>=32 chars).');
    process.exit(1);
}
app.use(
    session({
        store: new SQLiteStore({
            db: 'sessions.sqlite',
            dir: path.resolve(process.cwd(), 'data'),
            concurrentDB: false
        }),
        name: 'sid',
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: TRUST_PROXY || process.env.NODE_ENV === 'production',
            maxAge: 1000 * 60 * 60 * 12 // 12 hours
        }
    })
);

// CSRF protection (session-based)
app.use(csurf());

// Views
app.set('view engine', 'ejs');
app.set('views', path.resolve(process.cwd(), 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

// Static assets (cache aggressively; file names should be content-addressed if changed)
app.use('/public', express.static(path.resolve(process.cwd(), 'public'), { maxAge: '7d', immutable: true }));

// Attach common locals
app.use((req, res, next) => {
    res.locals.csp = getCspDirectives();
    res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
    res.locals.isAuthenticated = Boolean(req.session.userId);
    next();
});

// Attach user if logged in
app.use(attachUserToLocals);

// Health endpoint
app.get('/healthz', (req, res) => {
    res.type('text/plain').send('ok');
});

// Home
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/notes');
    }
    res.render('index');
});

// Routers
app.use('/auth', authLimiter, authRouter);
app.use('/notes', requireAuth, notesRouter);

// 404
app.use((req, res) => {
    res.status(404).render('error', { message: 'Page not found' });
});

// Error handler
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).render('error', { message: 'Invalid CSRF token' });
    }
    console.error(err);
    res.status(500).render('error', { message: 'An unexpected error occurred' });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
    console.log(`Secure Notes app listening on http://localhost:${PORT}`);
});


