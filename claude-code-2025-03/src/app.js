const express = require('express');
const path = require('path');
const morgan = require('morgan');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { v4: uuidv4 } = require('uuid');

const { connectDB } = require('./utils/db');
const config = require('./config');
const {
  helmetMiddleware,
  noFrames,
  csrfErrorHandler,
} = require('./middleware/security');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes');
const csrfRoutes = require('./routes/csrfRoutes');

// Initialize express app
const app = express();

// Set secure HTTP headers with helmet
app.use(helmetMiddleware);
app.use(noFrames);

// Request logging
if (config.isDevelopment) {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Parse JSON request bodies
app.use(express.json({ limit: '100kb' }));

// Parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '..', 'public')));

// Session configuration
app.use(
  session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: config.mongodb.uri,
      touchAfter: 24 * 3600, // time period in seconds
    }),
    cookie: config.session.cookie,
    genid: () => uuidv4(), // Generate a unique ID for each session
  })
);

// CSRF error handler
app.use(csrfErrorHandler);

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);
app.use('/api/csrf', csrfRoutes);

// API health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
  });
});

// Root route for the web app
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// 404 handler for API routes
app.use('/api/*', notFoundHandler);

// 404 handler for all other routes (return index.html for SPA)
app.use('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Global error handler
app.use(errorHandler);

// Connect to MongoDB and start server
const PORT = config.port;

const startServer = async () => {
  try {
    // Connect to MongoDB
    await connectDB();
    
    // Start the server
    app.listen(PORT, () => {
      console.log(`Server running in ${config.env} mode on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
if (require.main === module) {
  startServer();
}

// Export for testing
module.exports = app;