const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const cors = require('cors');
const connectDB = require('./config/db');
const errorHandler = require('./middleware/errorHandler');
const rateLimiter = require('./middleware/rateLimiter');

// Load env vars
dotenv.config();

// Connect to database
connectDB();

const app = express();

// Body parser
app.use(express.json({ limit: '10kb' }));

// Security middleware
app.use(helmet()); // Set secure HTTP headers
app.use(xss()); // Sanitize inputs
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://your-frontend-domain.com' : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
app.use('/api/', rateLimiter);

// Mount routers
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/notes', require('./routes/noteRoutes'));

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Resource not found'
  });
});

module.exports = app;