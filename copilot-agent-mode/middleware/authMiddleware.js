const jwt = require("jsonwebtoken");
const { AppError } = require("./errorMiddleware");
const User = require("../models/User");
const { asyncHandler } = require("../utils/asyncHandler");

// Protect routes - require authentication
const protect = asyncHandler(async (req, res, next) => {
  let token;

  // 1) Check if token exists in Authorization header or in cookies
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    // Get token from header
    token = req.headers.authorization.split(" ")[1];
  } else if (req.signedCookies.jwt) {
    // Get token from signed cookie
    token = req.signedCookies.jwt;
  }

  // 2) Check if token exists
  if (!token) {
    return next(
      new AppError("You are not logged in. Please log in to get access.", 401)
    );
  }

  try {
    // 3) Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 4) Check if user still exists
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return next(
        new AppError("The user belonging to this token no longer exists.", 401)
      );
    }

    // 5) Check if user changed password after the token was issued
    if (user.changedPasswordAfter(decoded.iat)) {
      return next(
        new AppError(
          "User recently changed password! Please log in again.",
          401
        )
      );
    }

    // Grant access to protected route
    req.user = user;
    next();
  } catch (error) {
    return next(
      new AppError("Authentication failed. Please log in again.", 401)
    );
  }
});

module.exports = {
  protect,
};
