const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const User = require("../models/User");
const { sendTokenResponse } = require("../middleware/auth");
const { ErrorResponse } = require("../middleware/errorHandler");

// In-memory store for login attempts (use Redis in production)
const loginAttempts = new Map();

/**
 * @desc    Register user
 * @route   POST /api/auth/register
 * @access  Public
 */
exports.register = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = User.findByUsername(username);
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    // Hash password with bcrypt
    const salt = await bcrypt.genSalt(
      parseInt(process.env.BCRYPT_ROUNDS) || 12
    );
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    User.create(user);

    // Send token response
    sendTokenResponse(user, 201, res);
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
exports.login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip;

    // Check for too many failed attempts
    const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: null };

    if (attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
      const remainingTime = Math.ceil(
        (attempts.lockedUntil - Date.now()) / 1000 / 60
      );
      return res.status(429).json({
        success: false,
        message: `Too many failed login attempts. Try again in ${remainingTime} minutes.`,
      });
    }

    // Find user
    const user = User.findByUsername(username);

    if (!user) {
      // Increment failed attempts
      attempts.count++;
      if (attempts.count >= parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5) {
        attempts.lockedUntil =
          Date.now() + (parseInt(process.env.LOCKOUT_TIME) || 900000);
      }
      loginAttempts.set(ip, attempts);

      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      // Increment failed attempts
      attempts.count++;
      if (attempts.count >= parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5) {
        attempts.lockedUntil =
          Date.now() + (parseInt(process.env.LOCKOUT_TIME) || 900000);
      }
      loginAttempts.set(ip, attempts);

      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Clear failed attempts on successful login
    loginAttempts.delete(ip);

    // Update last login
    User.updateLastLogin(user.id);

    // Send token response
    sendTokenResponse(user, 200, res);
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Logout user / clear cookie
 * @route   POST /api/auth/logout
 * @access  Private
 */
exports.logout = async (req, res, next) => {
  try {
    res.cookie("token", "none", {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });

    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (err) {
    next(err);
  }
};

/**
 * @desc    Get current logged in user
 * @route   GET /api/auth/me
 * @access  Private
 */
exports.getMe = async (req, res, next) => {
  try {
    const user = User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      data: {
        id: user.id,
        username: user.username,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      },
    });
  } catch (err) {
    next(err);
  }
};
