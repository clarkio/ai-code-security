/**
 * Authentication Routes
 * Secure user registration, login, logout, and token refresh
 */

const express = require("express");
const router = express.Router();

const User = require("../models/User");
const RefreshToken = require("../models/RefreshToken");
const { AuditLog, AUDIT_ACTIONS } = require("../models/AuditLog");
const {
  authenticate,
  generateTokens,
  setTokenCookie,
  clearTokenCookie,
} = require("../middleware/auth");
const { handleValidationErrors } = require("../middleware/validation");
const { authRateLimiter } = require("../middleware/security");
const {
  registerValidation,
  loginValidation,
  changePasswordValidation,
  refreshTokenValidation,
} = require("../validators");
const logger = require("../config/logger");
const config = require("../config");

/**
 * POST /api/auth/register
 * Register a new user
 */
router.post(
  "/register",
  authRateLimiter,
  registerValidation,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Check if user already exists (generic error to prevent enumeration)
      const existingUser =
        User.findByUsername(username) || User.findByEmail(email);
      if (existingUser) {
        // Use same timing as successful registration to prevent timing attacks
        await new Promise((resolve) => setTimeout(resolve, 100));

        return res.status(400).json({
          error: "Registration failed. Please try different credentials.",
        });
      }

      // Create user
      const user = await User.create(username, email, password);

      // Generate tokens
      const { accessToken } = generateTokens(user);
      const refreshTokenData = RefreshToken.create(user.id);

      // Set secure cookie
      setTokenCookie(res, accessToken);

      // Audit log
      AuditLog.log(AUDIT_ACTIONS.REGISTER, {
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });

      logger.info(`User registered: ${user.id}`);

      res.status(201).json({
        message: "Registration successful",
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
        accessToken,
        refreshToken: refreshTokenData.token,
        expiresIn: config.jwt.expiresIn,
      });
    } catch (error) {
      logger.error("Registration error:", error);
      res.status(500).json({
        error: "Registration failed. Please try again.",
      });
    }
  }
);

/**
 * POST /api/auth/login
 * Authenticate user and return tokens
 */
router.post(
  "/login",
  authRateLimiter,
  loginValidation,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { username, password } = req.body;

      // Find user
      const user = User.findByUsername(username);

      // Generic error message to prevent username enumeration
      const genericError = {
        error: "Invalid username or password",
      };

      if (!user) {
        // Perform dummy password check to prevent timing attacks
        await User.verifyPassword(password, "$2b$12$dummyhashfortimingatk");

        AuditLog.log(AUDIT_ACTIONS.LOGIN_FAILED, {
          ipAddress: req.ip,
          userAgent: req.get("User-Agent"),
          details: { reason: "User not found" },
        });

        return res.status(401).json(genericError);
      }

      // Check if account is locked
      if (User.isAccountLocked(user)) {
        AuditLog.log(AUDIT_ACTIONS.LOGIN_FAILED, {
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.get("User-Agent"),
          details: { reason: "Account locked" },
        });

        return res.status(401).json({
          error:
            "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
        });
      }

      // Verify password
      const isValid = await User.verifyPassword(password, user.password_hash);

      if (!isValid) {
        User.recordFailedLogin(user.id);

        // Check if this attempt caused a lockout
        const updatedUser = User.findById(user.id);
        if (User.isAccountLocked(updatedUser)) {
          AuditLog.log(AUDIT_ACTIONS.ACCOUNT_LOCKED, {
            userId: user.id,
            ipAddress: req.ip,
            userAgent: req.get("User-Agent"),
          });
        }

        AuditLog.log(AUDIT_ACTIONS.LOGIN_FAILED, {
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.get("User-Agent"),
          details: { reason: "Invalid password" },
        });

        return res.status(401).json(genericError);
      }

      // Reset failed attempts on successful login
      User.resetLoginAttempts(user.id);

      // Generate tokens
      const { accessToken } = generateTokens(user);
      const refreshTokenData = RefreshToken.create(user.id);

      // Set secure cookie
      setTokenCookie(res, accessToken);

      // Audit log
      AuditLog.log(AUDIT_ACTIONS.LOGIN_SUCCESS, {
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });

      logger.info(`User logged in: ${user.id}`);

      res.json({
        message: "Login successful",
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
        accessToken,
        refreshToken: refreshTokenData.token,
        expiresIn: config.jwt.expiresIn,
      });
    } catch (error) {
      logger.error("Login error:", error);
      res.status(500).json({
        error: "Login failed. Please try again.",
      });
    }
  }
);

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post(
  "/refresh",
  refreshTokenValidation,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { refreshToken } = req.body;

      // Verify refresh token
      const tokenData = RefreshToken.verify(refreshToken);

      if (!tokenData) {
        return res.status(401).json({
          error: "Invalid or expired refresh token",
          code: "INVALID_REFRESH_TOKEN",
        });
      }

      // Get user
      const user = User.findById(tokenData.user_id);
      if (!user) {
        RefreshToken.revoke(refreshToken);
        return res.status(401).json({
          error: "User not found",
          code: "USER_NOT_FOUND",
        });
      }

      // Revoke old refresh token (token rotation)
      RefreshToken.revoke(refreshToken);

      // Generate new tokens
      const { accessToken } = generateTokens(user);
      const newRefreshTokenData = RefreshToken.create(user.id);

      // Set secure cookie
      setTokenCookie(res, accessToken);

      // Audit log
      AuditLog.log(AUDIT_ACTIONS.TOKEN_REFRESH, {
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });

      res.json({
        accessToken,
        refreshToken: newRefreshTokenData.token,
        expiresIn: config.jwt.expiresIn,
      });
    } catch (error) {
      logger.error("Token refresh error:", error);
      res.status(500).json({
        error: "Token refresh failed",
      });
    }
  }
);

/**
 * POST /api/auth/logout
 * Logout user and revoke tokens
 */
router.post("/logout", authenticate, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    // Revoke refresh token if provided
    if (refreshToken) {
      RefreshToken.revoke(refreshToken);
    }

    // Clear cookie
    clearTokenCookie(res);

    // Audit log
    AuditLog.log(AUDIT_ACTIONS.LOGOUT, {
      userId: req.user.id,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
    });

    logger.info(`User logged out: ${req.user.id}`);

    res.json({ message: "Logout successful" });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({
      error: "Logout failed",
    });
  }
});

/**
 * POST /api/auth/logout-all
 * Logout from all devices
 */
router.post("/logout-all", authenticate, async (req, res) => {
  try {
    // Revoke all refresh tokens for user
    RefreshToken.revokeAllForUser(req.user.id);

    // Clear cookie
    clearTokenCookie(res);

    // Audit log
    AuditLog.log(AUDIT_ACTIONS.LOGOUT, {
      userId: req.user.id,
      ipAddress: req.ip,
      userAgent: req.get("User-Agent"),
      details: { allDevices: true },
    });

    logger.info(`User logged out from all devices: ${req.user.id}`);

    res.json({ message: "Logged out from all devices" });
  } catch (error) {
    logger.error("Logout all error:", error);
    res.status(500).json({
      error: "Logout failed",
    });
  }
});

/**
 * PUT /api/auth/password
 * Change password
 */
router.put(
  "/password",
  authenticate,
  changePasswordValidation,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      // Get full user record
      const user = User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      // Get password hash
      const fullUser = User.findByUsername(user.username);

      // Verify current password
      const isValid = await User.verifyPassword(
        currentPassword,
        fullUser.password_hash
      );
      if (!isValid) {
        return res.status(401).json({
          error: "Current password is incorrect",
        });
      }

      // Update password
      await User.updatePassword(req.user.id, newPassword);

      // Revoke all refresh tokens (force re-login)
      RefreshToken.revokeAllForUser(req.user.id);

      // Audit log
      AuditLog.log(AUDIT_ACTIONS.PASSWORD_CHANGE, {
        userId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });

      logger.info(`Password changed for user: ${req.user.id}`);

      res.json({
        message: "Password changed successfully. Please log in again.",
      });
    } catch (error) {
      logger.error("Password change error:", error);
      res.status(500).json({
        error: "Password change failed",
      });
    }
  }
);

/**
 * GET /api/auth/me
 * Get current user info
 */
router.get("/me", authenticate, (req, res) => {
  res.json({
    user: req.user,
  });
});

module.exports = router;
