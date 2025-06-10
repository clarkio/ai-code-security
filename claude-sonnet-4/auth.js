const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { body, validationResult } = require('express-validator')
const rateLimit = require('express-rate-limit')
const slowDown = require('express-slow-down')
const database = require('./database')

// In-memory brute force protection (consider Redis for production scaling)
const bruteForceAttempts = new Map()

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
})

// Slow down middleware for auth endpoints
const authSlowDown = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 2, // allow 2 requests per windowMs at full speed
  delayMs: () => 500, // slow down subsequent requests by 500ms per request
  validate: { delayMs: false } // disable warning
})

// Validation middleware
const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage(
      'Username must be 3-30 characters and contain only letters, numbers, and underscores'
    ),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage(
      'Password must be at least 8 characters with uppercase, lowercase, number, and special character'
    )
]

const validateLogin = [
  body('username')
    .notEmpty()
    .trim()
    .escape()
    .withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
]

const validateNote = [
  body('title')
    .isLength({ min: 1, max: 200 })
    .trim()
    .escape()
    .withMessage('Title must be 1-200 characters'),
  body('content')
    .isLength({ min: 1, max: 10000 })
    .trim()
    .withMessage('Content must be 1-10000 characters')
]

// Simple brute force protection middleware
const bruteForceProtection = (req, res, next) => {
  const key = req.ip + ':' + (req.body.username || 'unknown')
  const now = Date.now()
  const attempts = bruteForceAttempts.get(key) || {
    count: 0,
    lastAttempt: now
  }

  // Reset if more than 1 hour has passed
  if (now - attempts.lastAttempt > 60 * 60 * 1000) {
    attempts.count = 0
  }

  // Check if too many attempts
  if (attempts.count >= 5) {
    const timeSinceLastAttempt = now - attempts.lastAttempt
    const waitTime = Math.min(attempts.count * 60 * 1000, 30 * 60 * 1000) // Max 30 minutes

    if (timeSinceLastAttempt < waitTime) {
      return res.status(429).json({
        success: false,
        message: `Too many failed attempts. Try again in ${Math.ceil(
          (waitTime - timeSinceLastAttempt) / 60000
        )} minutes.`
      })
    }
  }

  // Store failed attempt (will be reset on successful login)
  req.bruteForceKey = key
  next()
}

// Helper to record failed attempt
const recordFailedAttempt = (key) => {
  const attempts = bruteForceAttempts.get(key) || {
    count: 0,
    lastAttempt: Date.now()
  }
  attempts.count++
  attempts.lastAttempt = Date.now()
  bruteForceAttempts.set(key, attempts)
}

// Helper to clear failed attempts on successful login
const clearFailedAttempts = (key) => {
  bruteForceAttempts.delete(key)
}

class AuthController {
  // User registration
  static async register (req, res) {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        })
      }

      const { username, email, password } = req.body

      // Check if user already exists
      const existingUser = await database.get(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [username, email]
      )

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'Username or email already exists'
        })
      }

      // Hash password
      const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12
      const passwordHash = await bcrypt.hash(password, saltRounds)

      // Create user
      const result = await database.run(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, passwordHash]
      )

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        userId: result.id
      })
    } catch (error) {
      console.error('Registration error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // User login
  static async login (req, res) {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        })
      }

      const { username, password } = req.body

      // Get user from database
      const user = await database.get(
        'SELECT * FROM users WHERE username = ? AND is_active = 1',
        [username]
      )

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        })
      }

      // Check if account is locked
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        return res.status(423).json({
          success: false,
          message: 'Account temporarily locked due to multiple failed attempts'
        })
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(
        password,
        user.password_hash
      )

      if (!isValidPassword) {
        // Increment failed login attempts
        const failedAttempts = user.failed_login_attempts + 1
        const lockUntil =
          failedAttempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null // Lock for 30 minutes after 5 failed attempts

        await database.run(
          'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
          [failedAttempts, lockUntil, user.id]
        )

        // Record brute force attempt
        recordFailedAttempt(req.bruteForceKey)

        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        })
      }

      // Reset failed login attempts on successful login
      await database.run(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
        [user.id]
      )

      // Clear brute force protection
      clearFailedAttempts(req.bruteForceKey)

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
      )

      // Set session
      req.session.userId = user.id
      req.session.username = user.username

      res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      })
    } catch (error) {
      console.error('Login error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }

  // User logout
  static async logout (req, res) {
    try {
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err)
          return res.status(500).json({
            success: false,
            message: 'Error logging out'
          })
        }

        res.clearCookie('connect.sid')
        res.json({
          success: true,
          message: 'Logout successful'
        })
      })
    } catch (error) {
      console.error('Logout error:', error)
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      })
    }
  }
}

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    })
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      })
    }
    req.user = user
    next()
  })
}

// Session authentication middleware
const authenticateSession = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required'
    })
  }
  req.user = {
    userId: req.session.userId,
    username: req.session.username
  }
  next()
}

module.exports = {
  AuthController,
  authenticateToken,
  authenticateSession,
  validateRegistration,
  validateLogin,
  validateNote,
  authLimiter,
  authSlowDown,
  bruteForceProtection
}
