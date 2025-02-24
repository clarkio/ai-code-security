const errorHandler = (err, req, res, next) => {
    // Log to console for dev
    console.error(err);
  
    let error = { ...err };
    error.message = err.message;
  
    // Mongoose bad ObjectId
    if (err.name === 'CastError') {
      const message = 'Resource not found';
      error = { message, status: 404 };
    }
  
    // Mongoose duplicate key
    if (err.code === 11000) {
      const message = 'Duplicate field value entered';
      error = { message, status: 400 };
    }
  
    // Mongoose validation error
    if (err.name === 'ValidationError') {
      const message = Object.values(err.errors).map(val => val.message);
      error = { message, status: 400 };
    }
  
    res.status(error.status || 500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  };
  
  module.exports = errorHandler;