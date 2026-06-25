"use strict";

/**
 * Password hashing with bcrypt.
 *
 * SECURITY:
 *  - bcrypt with cost factor 12 (good balance of security & performance as of 2024).
 *  - We never store or log plaintext passwords.
 *  - Comparison is constant-time (bcrypt handles this).
 */

const bcrypt = require("bcryptjs");

const BCRYPT_ROUNDS = 12;

async function hashPassword(plaintext) {
  return bcrypt.hash(plaintext, BCRYPT_ROUNDS);
}

async function verifyPassword(plaintext, hash) {
  if (!hash) return false;
  return bcrypt.compare(plaintext, hash);
}

module.exports = { hashPassword, verifyPassword };
