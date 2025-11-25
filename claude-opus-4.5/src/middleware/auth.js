/**
 * Authentication Middleware
 * JWT verification and authorization
 */

const jwt = require("jsonwebtoken");
const config = require("../config");
const User = require("../models/User");
const { AuditLog, AUDIT_ACTIONS } = require("../models/AuditLog");
const logger = require("../config/logger");

/**
 * Extract JWT from Authorization header or cookie
 */
function extractToken(req) {
  // Check Authorization header first (preferred)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }

  // Check cookie as fallback
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }

  return null;
}

/**
 * Authenticate request using JWT
 */
function authenticate(req, res, next) {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({
      error: "Authentication required",
      code: "AUTH_REQUIRED",
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.jwt.secret, {
      algorithms: ["HS256"], // Only allow HS256 to prevent algorithm confusion attacks
      issuer: "secure-notes-app",
      audience: "secure-notes-users",
    });

    // Check if user still exists
    const user = User.findById(decoded.sub);
    if (!user) {
      return res.status(401).json({
        error: "User no longer exists",
        code: "USER_NOT_FOUND",
      });
    }

    // Check if account is locked
    if (User.isAccountLocked(user)) {
      return res.status(401).json({
        error: "Account is temporarily locked",
        code: "ACCOUNT_LOCKED",
      });
    }

    // Attach user to request
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
    };

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Token expired",
        code: "TOKEN_EXPIRED",
      });
    }

    if (error.name === "JsonWebTokenError") {
      logger.warn(`Invalid JWT attempt: ${error.message}`);

      AuditLog.log(AUDIT_ACTIONS.UNAUTHORIZED_ACCESS, {
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
        details: { reason: "Invalid JWT" },
      });

      return res.status(401).json({
        error: "Invalid token",
        code: "INVALID_TOKEN",
      });
    }

    logger.error("Authentication error:", error);
    return res.status(500).json({
      error: "Authentication failed",
      code: "AUTH_ERROR",
    });
  }
}

/**
 * Generate access and refresh tokens
 */
function generateTokens(user) {
  const accessToken = jwt.sign(
    {
      sub: user.id,
      username: user.username,
    },
    config.jwt.secret,
    {
      algorithm: "HS256",
      expiresIn: config.jwt.expiresIn,
      issuer: "secure-notes-app",
      audience: "secure-notes-users",
    }
  );

  return { accessToken };
}

/**
 * Set secure cookie with access token
 */
function setTokenCookie(res, accessToken) {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // Prevent XSS access to cookie
    secure: config.cookie.secure, // Only send over HTTPS in production
    sameSite: config.cookie.sameSite, // CSRF protection
    maxAge: 15 * 60 * 1000, // 15 minutes
    path: "/",
  });
}

/**
 * Clear authentication cookies
 */
function clearTokenCookie(res) {
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: config.cookie.secure,
    sameSite: config.cookie.sameSite,
    path: "/",
  });
}

module.exports = {
  authenticate,
  generateTokens,
  setTokenCookie,
  clearTokenCookie,
  extractToken,
};
