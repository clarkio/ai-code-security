'use strict';

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const morgan = require('morgan');
const mongoose = require('mongoose');

const { authRouter } = require('./routes/auth');
const { notesRouter } = require('./routes/notes');
const path = require('path');

const app = express();

// Trust proxy for correct IPs when behind reverse proxies
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
    crossOriginResourcePolicy: { policy: 'same-site' }
}));

// CORS (configure allowlist via env)
const allowedOrigins = (process.env.CORS_ALLOWLIST || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: false
}));

// Logging (production: concise)
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Body parsing
app.use(express.json({ limit: '100kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// Compression
app.use(compression());

// NoSQL injection protection
app.use(mongoSanitize());

// Rate limiting
const limiter = rateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
    max: Number(process.env.RATE_LIMIT_MAX || 100),
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// Health
app.get('/healthz', (req, res) => res.status(200).json({ ok: true }));

// Routes
app.use('/api/auth', authRouter);
app.use('/api/notes', notesRouter);

// Minimal UI (static)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'app.html'));
});

// 404
app.use((req, res) => {
    return res.status(404).json({ error: 'Not Found' });
});

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    const status = err.status || 500;
    if (process.env.NODE_ENV !== 'production') {
        return res.status(status).json({ error: err.message || 'Server Error' });
    }
    return res.status(status).json({ error: 'Server Error' });
});

// DB connect and start
const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/secure-notes';

mongoose.connect(MONGODB_URI, { dbName: 'secure-notes' })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((e) => {
        console.error('Failed to connect to MongoDB', e);
        process.exit(1);
    });


