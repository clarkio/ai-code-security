const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { tokenStatements } = require('../db/database');

// Generate access token
function generateAccessToken(userId) {
  return jwt.sign(
    { 
      userId, 
      type: 'access',
      iat: Math.floor(Date.now() / 1000)
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      algorithm: 'HS256'
    }
  );
}

// Generate refresh token
function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Hash refresh token for storage
function hashToken(token) {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

// Save refresh token to database
async function saveRefreshToken(userId, token, expiresIn = 7 * 24 * 60 * 60 * 1000) {
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + expiresIn).toISOString();
  
  try {
    const result = await tokenStatements.create({
      user_id: userId,
      token_hash: tokenHash,
      expires_at: expiresAt
    });
    
    return result.lastID;
  } catch (error) {
    throw new Error('Failed to save refresh token');
  }
}

// Verify refresh token
async function verifyRefreshToken(token) {
  const tokenHash = hashToken(token);
  
  try {
    const storedToken = await tokenStatements.findByHash({ token_hash: tokenHash });
    
    if (!storedToken) {
      return { valid: false, reason: 'Token not found' };
    }
    
    if (storedToken.is_revoked) {
      return { valid: false, reason: 'Token has been revoked' };
    }
    
    if (new Date(storedToken.expires_at) < new Date()) {
      return { valid: false, reason: 'Token has expired' };
    }
    
    return { valid: true, userId: storedToken.user_id };
  } catch (error) {
    return { valid: false, reason: 'Token verification failed' };
  }
}

// Revoke refresh token
async function revokeRefreshToken(token) {
  const tokenHash = hashToken(token);
  
  try {
    const result = await tokenStatements.revoke({ token_hash: tokenHash });
    return result.changes > 0;
  } catch (error) {
    throw new Error('Failed to revoke token');
  }
}

// Revoke all refresh tokens for a user
async function revokeAllUserTokens(userId) {
  try {
    const result = await tokenStatements.revokeAllForUser({ user_id: userId });
    return result.changes;
  } catch (error) {
    throw new Error('Failed to revoke user tokens');
  }
}

// Hash password
async function hashPassword(password) {
  const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  return bcrypt.hash(password, rounds);
}

// Verify password
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Generate CSRF token
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Constant-time string comparison to prevent timing attacks
function secureCompare(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  saveRefreshToken,
  verifyRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens,
  hashPassword,
  verifyPassword,
  generateCSRFToken,
  secureCompare
};