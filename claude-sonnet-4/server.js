require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
const morgan = require('morgan')
const session = require('express-session')
const SQLiteStore = require('connect-sqlite3')(session)
const cookieParser = require('cookie-parser')
const path = require('path')
const database = require('./database')
const {
  AuthController,
  authenticateToken,
  validateRegistration,
  validateLogin,
  validateNote,
  authLimiter,
  authSlowDown,
  bruteForceProtection
} = require('./auth')
const NotesController = require('./notes')

const app = express()
const PORT = process.env.PORT || 3000

// Security Configuration
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
        scriptSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
)

// CORS Configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}
app.use(cors(corsOptions))

// Rate Limiting
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
})
app.use(generalLimiter)

// Logging
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined'))
} else {
  app.use(morgan('dev'))
}

// Body Parsing
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))
app.use(cookieParser())

// Session Configuration
app.use(
  session({
    store: new SQLiteStore({
      db: 'sessions.db',
      dir: './data'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: parseInt(process.env.SESSION_MAX_AGE) || 3600000, // 1 hour
      sameSite: 'strict'
    }
  })
)

// CSRF Protection Implementation
function generateCSRFToken () {
  return crypto.randomBytes(32).toString('hex')
}

const csrfProtection = (req, res, next) => {
  // Generate CSRF token for GET requests
  if (req.method === 'GET') {
    req.session.csrfToken = generateCSRFToken()
    return next()
  }

  // Verify CSRF token for other requests
  const tokenFromHeader = req.headers['x-csrf-token']
  const tokenFromSession = req.session.csrfToken

  if (
    !tokenFromHeader ||
    !tokenFromSession ||
    tokenFromHeader !== tokenFromSession
  ) {
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token'
    })
  }

  next()
}

// Serve static files
app.use(express.static('public'))

// Health check endpoint (no CSRF needed)
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  })
})

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({
    success: true,
    csrfToken: req.session.csrfToken
  })
})

// Authentication Routes (with rate limiting and brute force protection)
app.post(
  '/api/auth/register',
  authLimiter,
  authSlowDown,
  bruteForceProtection,
  csrfProtection,
  validateRegistration,
  AuthController.register
)

app.post(
  '/api/auth/login',
  authLimiter,
  authSlowDown,
  bruteForceProtection,
  csrfProtection,
  validateLogin,
  AuthController.login
)

app.post('/api/auth/logout', csrfProtection, AuthController.logout)

// Notes Routes (protected)
app.get('/api/notes', authenticateToken, NotesController.getAllNotes)

app.get('/api/notes/:id', authenticateToken, NotesController.getNoteById)

app.post(
  '/api/notes',
  authenticateToken,
  csrfProtection,
  validateNote,
  NotesController.createNote
)

app.put(
  '/api/notes/:id',
  authenticateToken,
  csrfProtection,
  validateNote,
  NotesController.updateNote
)

app.delete(
  '/api/notes/:id',
  authenticateToken,
  csrfProtection,
  NotesController.deleteNote
)

// Serve main HTML file for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// Global Error Handler
app.use((err, req, res, _next) => {
  console.error('Global error handler:', err)

  // Handle CSRF token errors
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token'
    })
  }

  // Handle validation errors
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON payload'
    })
  }

  // Generic error response
  res.status(500).json({
    success: false,
    message:
      process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message
  })
})

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  })
})

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully')
  await database.close()
  process.exit(0)
})

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully')
  await database.close()
  process.exit(0)
})

// Start server
async function startServer () {
  try {
    await database.initialize()

    app.listen(PORT, () => {
      console.log(`🚀 Secure Notes App running on port ${PORT}`)
      console.log(`📝 Environment: ${process.env.NODE_ENV}`)
      console.log('🔒 Security features enabled:')
      console.log('   ✓ Helmet security headers')
      console.log('   ✓ CORS protection')
      console.log('   ✓ Rate limiting')
      console.log('   ✓ CSRF protection')
      console.log('   ✓ Session security')
      console.log('   ✓ Input validation')
      console.log('   ✓ XSS protection')
      console.log('   ✓ SQL injection prevention')
      console.log('   ✓ Brute force protection')
      console.log('   ✓ Authentication & authorization')
    })
  } catch (error) {
    console.error('Failed to start server:', error)
    process.exit(1)
  }
}

startServer()

module.exports = app
