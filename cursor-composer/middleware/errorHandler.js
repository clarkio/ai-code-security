// Error handling middleware
const errorHandler = (err, req, res, next) => {
  // Log error for monitoring (but don't expose to client)
  console.error('Error:', err);

  // Don't leak sensitive error information
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Validation error',
      message: err.message 
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Generic error response - don't expose stack traces or internal details
  res.status(err.status || 500).json({
    error: 'An error occurred',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
};

module.exports = { errorHandler };

