const jwt = require("jsonwebtoken");

/**
 * Middleware to protect routes requiring authentication
 */
exports.protect = async (req, res, next) => {
  try {
    let token;

    // Check for token in Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }
    // Check for token in cookies
    else if (req.cookies.token) {
      token = req.cookies.token;
    }

    // Make sure token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authorized to access this route",
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Add user info to request
      req.user = {
        id: decoded.id,
        username: decoded.username,
      };

      next();
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Not authorized to access this route - invalid token",
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Server error during authentication",
    });
  }
};

/**
 * Generate JWT Token
 */
exports.getSignedJwtToken = (id, username) => {
  return jwt.sign({ id, username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
    algorithm: "HS256",
  });
};

/**
 * Send token response with secure cookie
 */
exports.sendTokenResponse = (user, statusCode, res) => {
  // Create token
  const token = this.getSignedJwtToken(user.id, user.username);

  const options = {
    expires: new Date(
      Date.now() + parseInt(process.env.JWT_COOKIE_EXPIRE) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true, // Prevents XSS attacks
    secure: process.env.NODE_ENV === "production", // HTTPS only in production
    sameSite: "strict", // CSRF protection
    signed: true, // Prevent tampering
  };

  res
    .status(statusCode)
    .cookie("token", token, options)
    .json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
      },
    });
};
