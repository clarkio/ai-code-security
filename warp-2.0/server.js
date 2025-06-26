require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const https = require('https');
const path = require('path');

// Import our modules
const database = require('./database');
const { AuthService, authenticate } = require('./auth');
const {
    validateRegistration,
    validateLogin,
    validateNote,
    handleValidationErrors,
    sanitizeAllInput,
    validateRateLimit
} = require('./validation');

// Initialize Express app
const app = express();
const authService = new AuthService();

// Trust proxy for accurate IP addresses behind reverse proxy
app.set('trust proxy', 1);

// Security middleware - CRITICAL for production
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginEmbedderPolicy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000'];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400 // 24 hours
}));

// Rate limiting - Multiple layers
const generalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit auth attempts
    message: {
        error: 'Too many authentication attempts, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
});

// Apply rate limiting
app.use(generalLimiter);
app.use('/api/auth', authLimiter);

// Compression for better performance
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined'));
} else {
    app.use(morgan('dev'));
}

// Body parsing with size limits
app.use(express.json({ 
    limit: '10mb',
    strict: true
}));
app.use(express.urlencoded({ 
    extended: false, 
    limit: '10mb' 
}));

// Input sanitization
app.use(sanitizeAllInput);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Serve static files securely
app.use('/public', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true,
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
    }
}));

// API Routes

// Authentication routes
app.post('/api/auth/register', 
    validateRegistration,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { username, email, password } = req.body;
            const user = await authService.register(username, email, password);
            
            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email
                }
            });
        } catch (error) {
            console.error('Registration error:', error.message);
            res.status(400).json({
                error: error.message
            });
        }
    }
);

app.post('/api/auth/login',
    validateLogin,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { usernameOrEmail, password } = req.body;
            const result = await authService.login(usernameOrEmail, password);
            
            res.json({
                success: true,
                message: 'Login successful',
                token: result.token,
                user: result.user
            });
        } catch (error) {
            console.error('Login error:', error.message);
            res.status(401).json({
                error: error.message
            });
        }
    }
);

app.post('/api/auth/logout',
    authenticate,
    async (req, res) => {
        try {
            const token = req.headers.authorization.substring(7);
            await authService.blacklistToken(token);
            
            res.json({
                success: true,
                message: 'Logout successful'
            });
        } catch (error) {
            console.error('Logout error:', error.message);
            res.status(500).json({
                error: 'Logout failed'
            });
        }
    }
);

// Notes routes - All require authentication
app.get('/api/notes',
    authenticate,
    async (req, res) => {
        try {
            const notes = await database.all(
                'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC',
                [req.user.id]
            );
            
            res.json({
                success: true,
                notes: notes
            });
        } catch (error) {
            console.error('Error fetching notes:', error.message);
            res.status(500).json({
                error: 'Failed to fetch notes'
            });
        }
    }
);

app.get('/api/notes/:id',
    authenticate,
    async (req, res) => {
        try {
            const noteId = parseInt(req.params.id);
            
            if (!noteId || noteId < 1) {
                return res.status(400).json({
                    error: 'Invalid note ID'
                });
            }
            
            const note = await database.get(
                'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?',
                [noteId, req.user.id]
            );
            
            if (!note) {
                return res.status(404).json({
                    error: 'Note not found'
                });
            }
            
            res.json({
                success: true,
                note: note
            });
        } catch (error) {
            console.error('Error fetching note:', error.message);
            res.status(500).json({
                error: 'Failed to fetch note'
            });
        }
    }
);

app.post('/api/notes',
    authenticate,
    validateNote,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { title, content } = req.body;
            
            const result = await database.run(
                'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)',
                [req.user.id, title, content]
            );
            
            const newNote = await database.get(
                'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
                [result.id]
            );
            
            res.status(201).json({
                success: true,
                message: 'Note created successfully',
                note: newNote
            });
        } catch (error) {
            console.error('Error creating note:', error.message);
            res.status(500).json({
                error: 'Failed to create note'
            });
        }
    }
);

app.put('/api/notes/:id',
    authenticate,
    validateNote,
    handleValidationErrors,
    async (req, res) => {
        try {
            const noteId = parseInt(req.params.id);
            const { title, content } = req.body;
            
            if (!noteId || noteId < 1) {
                return res.status(400).json({
                    error: 'Invalid note ID'
                });
            }
            
            // Check if note exists and belongs to user
            const existingNote = await database.get(
                'SELECT id FROM notes WHERE id = ? AND user_id = ?',
                [noteId, req.user.id]
            );
            
            if (!existingNote) {
                return res.status(404).json({
                    error: 'Note not found'
                });
            }
            
            // Update note
            await database.run(
                'UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                [title, content, noteId, req.user.id]
            );
            
            const updatedNote = await database.get(
                'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
                [noteId]
            );
            
            res.json({
                success: true,
                message: 'Note updated successfully',
                note: updatedNote
            });
        } catch (error) {
            console.error('Error updating note:', error.message);
            res.status(500).json({
                error: 'Failed to update note'
            });
        }
    }
);

app.delete('/api/notes/:id',
    authenticate,
    async (req, res) => {
        try {
            const noteId = parseInt(req.params.id);
            
            if (!noteId || noteId < 1) {
                return res.status(400).json({
                    error: 'Invalid note ID'
                });
            }
            
            const result = await database.run(
                'DELETE FROM notes WHERE id = ? AND user_id = ?',
                [noteId, req.user.id]
            );
            
            if (result.changes === 0) {
                return res.status(404).json({
                    error: 'Note not found'
                });
            }
            
            res.json({
                success: true,
                message: 'Note deleted successfully'
            });
        } catch (error) {
            console.error('Error deleting note:', error.message);
            res.status(500).json({
                error: 'Failed to delete note'
            });
        }
    }
);

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Route not found'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);
    
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({
            error: 'Invalid JSON in request body'
        });
    }
    
    res.status(500).json({
        error: 'Internal server error'
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await database.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    await database.close();
    process.exit(0);
});

// Start server
const PORT = process.env.PORT || 3000;

// Production HTTPS server
if (process.env.NODE_ENV === 'production' && process.env.SSL_CERT_PATH && process.env.SSL_KEY_PATH) {
    const sslOptions = {
        key: fs.readFileSync(process.env.SSL_KEY_PATH),
        cert: fs.readFileSync(process.env.SSL_CERT_PATH)
    };
    
    https.createServer(sslOptions, app).listen(PORT, () => {
        console.log(`🔒 Secure server running on https://localhost:${PORT}`);
        console.log('🛡️  Security features enabled:');
        console.log('   ✅ HTTPS/TLS encryption');
        console.log('   ✅ Helmet security headers');
        console.log('   ✅ CORS protection');
        console.log('   ✅ Rate limiting');
        console.log('   ✅ Input validation & sanitization');
        console.log('   ✅ JWT authentication');
        console.log('   ✅ Password hashing (bcrypt)');
        console.log('   ✅ SQL injection prevention');
        console.log('   ✅ XSS protection');
        
        // Clean up expired sessions periodically
        setInterval(() => {
            database.cleanupExpiredSessions();
        }, 60 * 60 * 1000); // Every hour
    });
} else {
    // Development HTTP server
    app.listen(PORT, () => {
        console.log(`🚀 Server running on http://localhost:${PORT}`);
        console.log('⚠️  Development mode - Use HTTPS in production!');
        console.log('🛡️  Security features enabled:');
        console.log('   ✅ Helmet security headers');
        console.log('   ✅ CORS protection');
        console.log('   ✅ Rate limiting');
        console.log('   ✅ Input validation & sanitization');
        console.log('   ✅ JWT authentication');
        console.log('   ✅ Password hashing (bcrypt)');
        console.log('   ✅ SQL injection prevention');
        console.log('   ✅ XSS protection');
        
        // Clean up expired sessions periodically
        setInterval(() => {
            database.cleanupExpiredSessions();
        }, 60 * 60 * 1000); // Every hour
    });
}

module.exports = app;
