const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please tell us your name'],
      trim: true,
      maxlength: [50, 'Name must be less than 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
      index: true,
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: [12, 'Password must be at least 12 characters long'],
      select: false, // Never show password in output
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      validate: {
        // This only works on CREATE and SAVE!!!
        validator: function (el) {
          return el === this.password;
        },
        message: 'Passwords are not the same!',
      },
    },
    passwordChangedAt: {
      type: Date,
      select: false,
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
    accountStatus: {
      type: String,
      enum: ['pending', 'active', 'locked', 'suspended', 'deactivated'],
      default: 'pending',
    },
    role: {
      type: String,
      enum: ['user', 'admin', 'moderator'],
      default: 'user',
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
      select: false,
    },
    lockedAt: {
      type: Date,
      select: false,
    },
    lastLoginAt: {
      type: Date,
      select: false,
    },
    lastLoginIp: {
      type: String,
      select: false,
    },
    lastUserAgent: {
      type: String,
      select: false,
    },
    lastActiveAt: {
      type: Date,
      default: Date.now,
      select: false,
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorSecret: {
      type: String,
      select: false,
    },
    twoFactorRecoveryCodes: {
      type: [String],
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Index for better query performance
userSchema.index({ email: 1 });

// Document middleware: runs before .save() and .create()
userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000; // 1 second in the past to ensure token is created after
  next();
});

// Query middleware
userSchema.pre(/^find/, function (next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  next();
});

// Instance methods

// Check if password is correct
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if user changed password after the token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false; // Not changed
};

// Generate password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  // Token expires in 10 minutes
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  
  return resetToken;
};

// Generate 2FA secret
userSchema.methods.generateTwoFactorSecret = function () {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `SecureNotes:${this.email}`,
  });
  
  this.twoFactorSecret = secret.base32;
  this.twoFactorRecoveryCodes = Array(8).fill().map(() => crypto.randomBytes(5).toString('hex'));
  
  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url,
    recoveryCodes: this.twoFactorRecoveryCodes,
  };
};

// Verify 2FA token
userSchema.methods.verifyTwoFactorToken = function (token) {
  return speakeasy.totp.verify({
    secret: this.twoFactorSecret,
    encoding: 'base32',
    token,
    window: 1, // Allow 1 step (30s) before/after current time
  });
};

// Generate 2FA recovery code
userSchema.methods.generateRecoveryCodes = function () {
  this.twoFactorRecoveryCodes = Array(8).fill().map(() => crypto.randomBytes(5).toString('hex'));
  return this.twoFactorRecoveryCodes;
};

// Verify recovery code and remove it if valid
userSchema.methods.verifyRecoveryCode = function (code) {
  const index = this.twoFactorRecoveryCodes.indexOf(code);
  if (index === -1) return false;
  
  // Remove used recovery code
  this.twoFactorRecoveryCodes.splice(index, 1);
  return true;
};

// Account lockout on too many failed login attempts
userSchema.methods.incrementLoginAttempts = async function () {
  // If we have a previous lock that has expired, restart the failed login count
  if (this.lockedAt && this.lockedAt < new Date(Date.now() - 30 * 60 * 1000)) {
    return await User.findByIdAndUpdate(
      this._id,
      {
        $set: { failedLoginAttempts: 1 },
        $unset: { lockedAt: 1 },
      },
      { new: true, runValidators: true }
    );
  }
  
  // Increment failed login attempts
  const updates = { $inc: { failedLoginAttempts: 1 } };
  
  // Lock the account if we've reached max attempts
  if (this.failedLoginAttempts + 1 >= 5) {
    updates.$set = { 
      accountStatus: 'locked',
      lockedAt: Date.now() 
    };
  }
  
  return await User.findByIdAndUpdate(
    this._id,
    updates,
    { new: true, runValidators: true }
  );
};

// Unlock user account
userSchema.methods.unlockAccount = async function () {
  return await User.findByIdAndUpdate(
    this._id,
    {
      $set: { accountStatus: 'active' },
      $unset: { 
        lockedAt: 1,
        failedLoginAttempts: 1 
      },
    },
    { new: true, runValidators: true }
  );
};

const User = mongoose.model('User', userSchema);

module.exports = User;
