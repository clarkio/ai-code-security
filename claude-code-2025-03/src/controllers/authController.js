const User = require('../models/user');
const createError = require('http-errors');

// Register a new user
const register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    // Check if username already exists
    const existingUsername = await User.findOne({ username: username.toLowerCase() });
    if (existingUsername) {
      return next(createError(400, 'Username already exists'));
    }

    // Check if email already exists
    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail) {
      return next(createError(400, 'Email already in use'));
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
    });

    await user.save();

    // Success response (don't return user data)
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
    });
  } catch (error) {
    next(error);
  }
};

// Login user
const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username: username.toLowerCase() });
    
    // Check if user exists
    if (!user) {
      return next(createError(401, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.isLocked) {
      return next(
        createError(
          403,
          `Account is temporarily locked. Try again later.`
        )
      );
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    
    if (!isMatch) {
      // Increment login attempts and potentially lock account
      await user.incrementLoginAttempts();
      return next(createError(401, 'Invalid credentials'));
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Create session
    req.session.user = {
      id: user._id,
      username: user.username,
    };

    // Success response
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    next(error);
  }
};

// Logout user
const logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Could not log out, please try again',
      });
    }
    
    res.clearCookie('connect.sid');
    
    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  });
};

// Get current user info
const getCurrentUser = (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.session.user.id,
      username: req.session.user.username,
    },
  });
};

module.exports = {
  register,
  login,
  logout,
  getCurrentUser,
};