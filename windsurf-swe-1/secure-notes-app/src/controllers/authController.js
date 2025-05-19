const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
});

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, req, res) => {
  // Generate access token
  const accessToken = signToken(user._id);
  
  // Generate refresh token
  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
  );
  
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Set cookie options
  const accessTokenCookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined,
    path: '/',
  };
  
  const refreshTokenCookieOptions = {
    ...accessTokenCookieOptions,
    expires: new Date(
      Date.now() + process.env.JWT_REFRESH_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    path: '/api/v1/auth/refresh-token',
  };

  // Remove sensitive data from output
  user.password = undefined;
  user.active = undefined;
  user.__v = undefined;

  // Set cookies
  res.cookie('access_token', accessToken, accessTokenCookieOptions);
  res.cookie('refresh_token', refreshToken, refreshTokenCookieOptions);

  // Add security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self';",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': "geolocation=(), microphone=(), camera=()",
  });

  // Prepare user data for response
  const userData = {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    photo: user.photo,
    lastLoginAt: user.lastLoginAt,
    twoFactorEnabled: user.twoFactorEnabled || false,
    accountStatus: user.accountStatus,
  };

  // If 2FA is enabled but not yet verified, don't send the access token
  if (user.twoFactorEnabled && !req.twoFactorVerified) {
    return res.status(202).json({
      status: 'success',
      message: 'Two-factor authentication required',
      twoFactorRequired: true,
      tempToken: signToken(user._id, '10m'), // Short-lived token for 2FA verification
    });
  }

  // Send response with user data and tokens
  res.status(statusCode).json({
    status: 'success',
    data: {
      user: userData,
      accessToken,
      refreshToken,
    },
  });
};

// Apply rate limiting to signup and login endpoints
exports.authLimiter = authLimiter;

// 2FA Methods
exports.setupTwoFactor = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    // Generate a new 2FA secret
    const result = user.generateTwoFactorSecret();
    await user.save({ validateBeforeSave: false });

    // Return the secret and QR code URL for the authenticator app
    res.status(200).json({
      status: 'success',
      data: {
        secret: result.secret,
        otpauthUrl: result.otpauthUrl,
        recoveryCodes: result.recoveryCodes, // Show only once
      },
    });
  } catch (err) {
    next(err);
  }
};

exports.verifyTwoFactor = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) {
      return next(new AppError('Please provide the 2FA token', 400));
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    // Verify the 2FA token
    const isVerified = user.verifyTwoFactorToken(token);
    if (!isVerified) {
      return next(new AppError('Invalid 2FA token', 400));
    }

    // Enable 2FA for the user
    user.twoFactorEnabled = true;
    await user.save({ validateBeforeSave: false });

    // Mark 2FA as verified for this session
    req.twoFactorVerified = true;

    // Create and send new tokens
    createSendToken(user, 200, req, res);
  } catch (err) {
    next(err);
  }
};

exports.disableTwoFactor = async (req, res, next) => {
  try {
    const { password } = req.body;
    if (!password) {
      return next(new AppError('Please provide your password', 400));
    }

    const user = await User.findById(req.user.id).select('+password');
    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect password', 401));
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorRecoveryCodes = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Two-factor authentication has been disabled',
    });
  } catch (err) {
    next(err);
  }
};

exports.verifyTwoFactorRecovery = async (req, res, next) => {
  try {
    const { email, recoveryCode } = req.body;
    if (!email || !recoveryCode) {
      return next(new AppError('Please provide email and recovery code', 400));
    }

    const user = await User.findOne({ email });
    if (!user) {
      return next(new AppError('No user found with that email', 404));
    }

    // Verify recovery code
    const isValidRecoveryCode = user.verifyRecoveryCode(recoveryCode);
    if (!isValidRecoveryCode) {
      return next(new AppError('Invalid recovery code', 400));
    }

    // Disable 2FA since they're using a recovery code
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorRecoveryCodes = undefined;
    await user.save({ validateBeforeSave: false });

    // Mark 2FA as verified for this session
    req.twoFactorVerified = true;

    // Create and send new tokens
    createSendToken(user, 200, req, res);
  } catch (err) {
    next(err);
  }
};

// Session Management
exports.refreshToken = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refresh_token || req.body.refreshToken;
    if (!refreshToken) {
      return next(new AppError('No refresh token provided', 401));
    }

    // Verify refresh token
    const decoded = await promisify(jwt.verify)(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );

    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(new AppError('The user belonging to this token no longer exists', 401));
    }

    // Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User recently changed password! Please log in again', 401));
    }

    // Create new tokens
    createSendToken(currentUser, 200, req, res);
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return next(new AppError('Invalid or expired refresh token', 401));
    }
    next(err);
  }
};

exports.getActiveSessions = async (req, res, next) => {
  try {
    // In a real app, you would track active sessions in the database
    // This is a simplified version
    res.status(200).json({
      status: 'success',
      data: {
        sessions: [{
          id: 'current-session',
          ip: req.ip,
          userAgent: req.get('user-agent'),
          lastActive: new Date(),
          current: true,
        }],
      },
    });
  } catch (err) {
    next(err);
  }
};

exports.revokeSession = async (req, res, next) => {
  try {
    const { sessionId } = req.params;
    // In a real app, you would invalidate the specific session token
    // This is a simplified version that just clears all tokens
    
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    
    res.status(200).json({
      status: 'success',
      message: 'Session revoked successfully',
    });
  } catch (err) {
    next(err);
  }
};

exports.revokeAllSessions = async (req, res, next) => {
  try {
    // In a real app, you would invalidate all refresh tokens for the user
    // and update the passwordChangedAt timestamp
    const user = await User.findById(req.user.id);
    user.passwordChangedAt = Date.now() - 1000; // Ensure all tokens are invalid
    await user.save({ validateBeforeSave: false });
    
    // Clear cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    
    res.status(200).json({
      status: 'success',
      message: 'All sessions have been revoked',
    });
  } catch (err) {
    next(err);
  }
};

// User Management
exports.lockUserAccount = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    // Prevent locking admin accounts
    if (user.role === 'admin') {
      return next(new AppError('Cannot lock admin accounts', 403));
    }

    user.accountStatus = 'locked';
    user.lockedAt = Date.now();
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'User account has been locked',
    });
  } catch (err) {
    next(err);
  }
};

exports.unlockUserAccount = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return next(new AppError('No user found with that ID', 404));
    }

    user.accountStatus = 'active';
    user.failedLoginAttempts = 0;
    user.lockedAt = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'User account has been unlocked',
    });
  } catch (err) {
    next(err);
  }
};

exports.signup = async (req, res, next) => {
  try {
    const { name, email, password, passwordConfirm } = req.body;

    // 1) Input validation
    if (!name || !email || !password || !passwordConfirm) {
      return next(new AppError('Please provide all required fields', 400));
    }

    // 2) Check password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
    if (!passwordRegex.test(password)) {
      return next(new AppError(
        'Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character',
        400
      ));
    }

    // 3) Check if user already exists with the same email (case-insensitive)
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (existingUser) {
      return next(
        new AppError('Email already in use. Please use a different email.', 400)
      );
    }

    // 4) Create new user with additional security fields
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      passwordConfirm,
      lastActiveAt: Date.now(),
      accountStatus: 'active',
      failedLoginAttempts: 0,
    });

    // 5) Generate JWT and log user in
    createSendToken(newUser, 201, req, res);
  } catch (err) {
    // Handle duplicate key errors
    if (err.code === 11000) {
      return next(new AppError('Email already in use. Please use a different email.', 400));
    }
    next(err);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent') || 'unknown';

    // 1) Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide both email and password', 400));
    }

    // 2) Get user from database (case-insensitive email match)
    const user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } })
      .select('+password +failedLoginAttempts +accountStatus +lastLoginAttempt');

    // 3) Check if account is locked
    if (user?.accountStatus === 'locked') {
      return next(
        new AppError('Your account has been locked due to too many failed login attempts. Please reset your password.', 401)
      );
    }

    // 4) Check if user exists and password is correct
    if (!user || !(await user.correctPassword(password, user.password))) {
      // Increment failed login attempts
      if (user) {
        const updatedUser = await user.incrementLoginAttempts();
        
        // Lock account after 5 failed attempts
        if (updatedUser.failedLoginAttempts >= 5) {
          await User.findByIdAndUpdate(user._id, { 
            accountStatus: 'locked',
            lockedAt: Date.now() 
          });
          
          // Send email notification about account lock
          await sendEmail({
            email: user.email,
            subject: 'Your account has been locked',
            message: `Your account has been locked due to multiple failed login attempts. Please reset your password to unlock your account.`
          });
          
          return next(
            new AppError('Your account has been locked due to too many failed login attempts. Please reset your password.', 401)
          );
        }
      }
      
      // Log failed login attempt
      console.warn(`Failed login attempt for email: ${email} from IP: ${ip} (User-Agent: ${userAgent})`);
      
      // Generic error message to avoid user enumeration
      return next(new AppError('Incorrect email or password', 401));
    }

    // 5) Check if account is active
    if (user.accountStatus !== 'active') {
      return next(
        new AppError('Your account is not active. Please contact support.', 403)
      );
    }

    // 6) Reset login attempts and update last login
    user.failedLoginAttempts = 0;
    user.lastLoginAt = Date.now();
    user.lastLoginIp = ip;
    user.lastUserAgent = userAgent;
    await user.save({ validateBeforeSave: false });

    // 7) Generate JWT and log user in
    createSendToken(user, 200, req, res);
  } catch (err) {
    console.error('Login error:', err);
    next(new AppError('An error occurred during login. Please try again later.', 500));
  }
};

exports.protect = async (req, res, next) => {
  try {
    // 1) Get token from header, cookies or body
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.access_token) {
      token = req.cookies.access_token;
    } else if (req.body.token) {
      token = req.body.token;
    }

    if (!token) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }

    // 2) Verify token
    let decoded;
    try {
      decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return next(new AppError('Invalid or expired token. Please log in again.', 401));
      }
      return next(err);
    }

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError('The user belonging to this token no longer exists.', 401)
      );
    }

    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(
        new AppError('User recently changed password! Please log in again.', 401)
      );
    }

    // 5) Check if account is active
    if (currentUser.accountStatus !== 'active') {
      return next(
        new AppError('Your account has been deactivated. Please contact support.', 403)
      );
    }

    // 6) Check if 2FA is required but not verified
    if (currentUser.twoFactorEnabled && !req.twoFactorVerified) {
      // If this is a 2FA verification request, allow it to proceed
      const is2FARoute = req.path.endsWith('/2fa/verify') || 
                        req.path.endsWith('/2fa/verify-recovery');
      
      if (!is2FARoute) {
        return res.status(202).json({
          status: 'success',
          message: 'Two-factor authentication required',
          twoFactorRequired: true,
        });
      }
    }

    // 7) Update last active timestamp (throttle to once per 5 minutes)
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    if (!currentUser.lastActiveAt || currentUser.lastActiveAt < fiveMinutesAgo) {
      currentUser.lastActiveAt = new Date();
      await currentUser.save({ validateBeforeSave: false });
    }

    // 8) GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (err) {
    next(err);
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array of allowed roles ['admin', 'lead-guide']. role='user'
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

exports.forgotPassword = async (req, res, next) => {
  try {
    // 1) Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return next(new AppError('There is no user with that email address.', 404));
    }

    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // 3) Send it to user's email
    const resetURL = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message,
      });

      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!',
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return next(
        new AppError(
          'There was an error sending the email. Try again later!',
          500
        )
      );
    }
  } catch (err) {
    next(err);
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    // 1) Get user based on the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // 3) Update changedPasswordAt property for the user
    // 4) Log the user in, send JWT
    createSendToken(user, 200, req, res);
  } catch (err) {
    next(err);
  }
};

exports.updatePassword = async (req, res, next) => {
  try {
    // 1) Get user from collection
    const user = await User.findById(req.user.id).select('+password');

    // 2) Check if POSTed current password is correct
    if (
      !user ||
      !(await user.correctPassword(req.body.passwordCurrent, user.password))
    ) {
      return next(new AppError('Your current password is wrong.', 401));
    }

    // 3) If so, update password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    // User.findByIdAndUpdate will NOT work as intended!

    // 4) Log user in, send JWT
    createSendToken(user, 200, req, res);
  } catch (err) {
    next(err);
  }
};
