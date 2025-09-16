const crypto = require('crypto');

/**
 * Generate a secure random string for keys and tokens
 * @param {number} length - Length of the random string
 * @returns {string} Base64 encoded random string
 */
function generateSecureRandom(length = 32) {
  return crypto.randomBytes(length).toString('base64');
}

/**
 * Generate a 256-bit encryption key
 * @returns {string} Base64 encoded 256-bit key
 */
function generateEncryptionKey() {
  return crypto.randomBytes(32).toString('base64'); // 256 bits = 32 bytes
}

/**
 * Validate if a string is a valid base64 encoded key of specified length
 * @param {string} key - The key to validate
 * @param {number} expectedBytes - Expected key length in bytes
 * @returns {boolean} True if valid
 */
function isValidKey(key, expectedBytes = 32) {
  try {
    const buffer = Buffer.from(key, 'base64');
    return buffer.length === expectedBytes;
  } catch (error) {
    return false;
  }
}

/**
 * Constant-time string comparison to prevent timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings are equal
 */
function constantTimeCompare(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    // eslint-disable-next-line no-bitwise
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

module.exports = {
  generateSecureRandom,
  generateEncryptionKey,
  isValidKey,
  constantTimeCompare,
};
