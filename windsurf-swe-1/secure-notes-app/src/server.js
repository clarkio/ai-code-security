require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const morgan = require('morgan');
const { StatusCodes } = require('http-status-codes');

// Import routes
const authRoutes = require('./routes/auth');
const noteRoutes = require('./routes/notes');
const healthRoutes = require('./routes/health');

// Initialize express app
const app = express();

// Enable trust proxy for rate limiting and secure cookies
app.set('trust proxy', 1);

// Set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit requests from same IP
const limiter = rateLimit({
  max: process.env.RATE_LIMIT_MAX || 100,
  windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
  message: 'Too many requests from this IP, please try again later',
});
app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(
  hpp({
    whitelist: ['title', 'content', 'createdAt', 'updatedAt'],
  })
);

// Compression middleware for responses
app.use(compression());

// Test middleware
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

// Enable CORS with specific origin
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : 'http://localhost:3000'
    : process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200, // Some legacy browsers (IE11, various SmartTVs) choke on 204
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

// API routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/notes', noteRoutes);
app.use('/api/v1/health', healthRoutes);

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  
  // All remaining requests return the React app, so it can handle routing
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../client/build', 'index.html'));
  });
}

// 404 handler - catch all unhandled routes
app.all('*', (req, res, next) => {
  res.status(StatusCodes.NOT_FOUND).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// Global error handling middleware
app.use((err, req, res, next) => {
  // Log the error for debugging
  console.error(`[${new Date().toISOString()}] Error: ${err.message}`);
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    err.statusCode = StatusCodes.UNAUTHORIZED;
    err.message = 'Invalid token. Please log in again!';
  }
  
  if (err.name === 'TokenExpiredError') {
    err.statusCode = StatusCodes.UNAUTHORIZED;
    err.message = 'Your token has expired! Please log in again.';
  }
  
  // Handle validation errors
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(StatusCodes.BAD_REQUEST).json({
      status: 'fail',
      message: `Validation error: ${messages.join('. ')}`
    });
  }
  
  // Handle duplicate field errors
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `Duplicate field value: ${field}. Please use another value!`;
    return res.status(StatusCodes.BAD_REQUEST).json({
      status: 'fail',
      message
    });
  }
  
  // Default error handling
  const statusCode = err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;
  const message = err.message || 'Something went wrong!';
  
  // Don't leak error details in production
  const errorResponse = {
    status: 'error',
    message,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      error: err
    })
  };
  
  res.status(statusCode).json(errorResponse);
});

// Connect to MongoDB and start server
const PORT = process.env.PORT || 3000;

// Create HTTP server
const server = app.listen(PORT, async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
    });
    
    console.log('✅ Connected to MongoDB');
    console.log(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    // Close server if database connection fails
    server.close(() => {
      console.log('💥 Server closed due to database connection error');
      process.exit(1);
    });
  }
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  
  // Close server & exit process
  server.close(() => {
    console.log('💥 Process terminated!');
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.error(err.name, err.message);
  
  // Close server & exit process
  server.close(() => {
    console.log('💥 Process terminated!');
    process.exit(1);
  });
});

// Graceful shutdown for SIGTERM (e.g., Docker stop)
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
    process.exit(0);
  });
});

// Graceful shutdown for SIGINT (e.g., Ctrl+C)
process.on('SIGINT', () => {
  console.log('👋 SIGINT RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated!');
    process.exit(0);
  });
});

module.exports = { app, server };
