const crypto = require('crypto');
const config = require('../config/environment');
const logger = require('../utils/logger');

class EncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16; // 128 bits
    this.tagLength = 16; // 128 bits
    
    // Load encryption keys from environment
    this.primaryKey = this.loadKey(config.encryption.key);
    this.rotationKey = config.encryption.rotationKey ? 
      this.loadKey(config.encryption.rotationKey) : null;
  }

  /**
   * Load and validate encryption key from base64 string
   */
  loadKey(keyString) {
    try {
      if (!keyString) {
        throw new Error('Encryption key is required');
      }

      const key = Buffer.from(keyString, 'base64');
      
      if (key.length !== this.keyLength) {
        throw new Error(`Encryption key must be ${this.keyLength} bytes (${this.keyLength * 8} bits)`);
      }

      return key;
    } catch (error) {
      logger.error('Failed to load encryption key', {
        error: error.message
      });
      throw new Error('Invalid encryption key configuration');
    }
  }

  /**
   * Encrypt plaintext data
   */
  encrypt(plaintext) {
    try {
      if (!plaintext || typeof plaintext !== 'string') {
        throw new Error('Plaintext must be a non-empty string');
      }

      // Generate random IV for each encryption
      const iv = crypto.randomBytes(this.ivLength);
      
      // Create cipher with GCM mode
      const cipher = crypto.createCipheriv(this.algorithm, this.primaryKey, iv);
      
      // Encrypt the data
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag
      const tag = cipher.getAuthTag();
      
      // Combine IV, tag, and encrypted data
      const result = {
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        encrypted: encrypted,
        keyVersion: 1 // Track which key was used for future rotation
      };

      return JSON.stringify(result);

    } catch (error) {
      logger.error('Encryption failed', {
        error: error.message
      });
      
      // Re-throw validation errors with original message
      if (error.message === 'Plaintext must be a non-empty string') {
        throw error;
      }
      
      throw new Error('Encryption operation failed');
    }
  }

  /**
   * Decrypt encrypted data
   */
  decrypt(encryptedData) {
    try {
      if (!encryptedData || typeof encryptedData !== 'string') {
        throw new Error('Encrypted data must be a non-empty string');
      }

      // Parse encrypted data
      const data = JSON.parse(encryptedData);
      const { iv, tag, encrypted, keyVersion } = data;

      if (!iv || !tag || !encrypted) {
        throw new Error('Invalid encrypted data format');
      }

      // Select appropriate key based on version
      const key = this.selectDecryptionKey(keyVersion);
      
      // Create decipher with GCM mode
      const decipher = crypto.createDecipheriv(this.algorithm, key, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(Buffer.from(tag, 'hex'));
      
      // Decrypt the data
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;

    } catch (error) {
      logger.error('Decryption failed', {
        error: error.message
      });
      
      // Re-throw validation errors with original message
      if (error.message === 'Encrypted data must be a non-empty string' || 
          error.message === 'Invalid encrypted data format') {
        throw error;
      }
      
      throw new Error('Decryption operation failed');
    }
  }

  /**
   * Select appropriate key for decryption based on version
   */
  selectDecryptionKey(keyVersion) {
    switch (keyVersion) {
      case 1:
        return this.primaryKey;
      case 2:
        if (!this.rotationKey) {
          throw new Error('Rotation key not available for decryption');
        }
        return this.rotationKey;
      default:
        logger.warn('Unknown key version, using primary key', {
          keyVersion
        });
        return this.primaryKey;
    }
  }

  /**
   * Re-encrypt data with new key (for key rotation)
   */
  reencrypt(encryptedData) {
    try {
      // Decrypt with old key
      const plaintext = this.decrypt(encryptedData);
      
      // Encrypt with new key (rotation key becomes primary)
      return this.encryptWithRotationKey(plaintext);

    } catch (error) {
      logger.error('Re-encryption failed', {
        error: error.message
      });
      throw new Error('Re-encryption operation failed');
    }
  }

  /**
   * Encrypt with rotation key (used during key rotation)
   */
  encryptWithRotationKey(plaintext) {
    try {
      if (!this.rotationKey) {
        throw new Error('Rotation key not available');
      }

      if (!plaintext || typeof plaintext !== 'string') {
        throw new Error('Plaintext must be a non-empty string');
      }

      // Generate random IV for each encryption
      const iv = crypto.randomBytes(this.ivLength);
      
      // Create cipher with GCM mode using rotation key
      const cipher = crypto.createCipheriv(this.algorithm, this.rotationKey, iv);
      
      // Encrypt the data
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag
      const tag = cipher.getAuthTag();
      
      // Combine IV, tag, and encrypted data with new key version
      const result = {
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        encrypted: encrypted,
        keyVersion: 2 // Mark as encrypted with rotation key
      };

      return JSON.stringify(result);

    } catch (error) {
      logger.error('Encryption with rotation key failed', {
        error: error.message
      });
      throw new Error('Rotation key encryption operation failed');
    }
  }

  /**
   * Rotate encryption keys (promote rotation key to primary)
   */
  rotateKeys() {
    try {
      if (!this.rotationKey) {
        throw new Error('No rotation key available for key rotation');
      }

      logger.info('Starting key rotation process');

      // Store old primary key for potential rollback
      const oldPrimaryKey = this.primaryKey;

      // Promote rotation key to primary
      this.primaryKey = this.rotationKey;
      this.rotationKey = null;

      logger.info('Key rotation completed successfully', {
        newKeyVersion: 2,
        rotationKeyCleared: true
      });

      return {
        success: true,
        newKeyVersion: 2,
        message: 'Key rotation completed successfully'
      };

    } catch (error) {
      logger.error('Key rotation failed', {
        error: error.message
      });
      throw new Error('Key rotation operation failed');
    }
  }

  /**
   * Generate a new encryption key
   */
  static generateKey() {
    const key = crypto.randomBytes(32); // 256 bits
    return key.toString('base64');
  }

  /**
   * Hash data using SHA-256 (for non-reversible hashing)
   */
  hash(data) {
    try {
      if (!data || typeof data !== 'string') {
        throw new Error('Data must be a non-empty string');
      }

      return crypto
        .createHash('sha256')
        .update(data)
        .digest('hex');

    } catch (error) {
      logger.error('Hashing failed', {
        error: error.message
      });
      throw new Error('Hashing operation failed');
    }
  }

  /**
   * Create HMAC for data integrity verification
   */
  createHMAC(data) {
    try {
      if (!data || typeof data !== 'string') {
        throw new Error('Data must be a non-empty string');
      }

      return crypto
        .createHmac('sha256', this.primaryKey)
        .update(data)
        .digest('hex');

    } catch (error) {
      logger.error('HMAC creation failed', {
        error: error.message
      });
      throw new Error('HMAC creation failed');
    }
  }

  /**
   * Verify HMAC for data integrity
   */
  verifyHMAC(data, expectedHmac) {
    try {
      const actualHmac = this.createHMAC(data);
      
      // Use timing-safe comparison to prevent timing attacks
      return crypto.timingSafeEqual(
        Buffer.from(actualHmac, 'hex'),
        Buffer.from(expectedHmac, 'hex')
      );

    } catch (error) {
      logger.error('HMAC verification failed', {
        error: error.message
      });
      return false;
    }
  }

  /**
   * Securely compare two strings to prevent timing attacks
   */
  static timingSafeEqual(a, b) {
    try {
      if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
      }

      if (a.length !== b.length) {
        return false;
      }

      return crypto.timingSafeEqual(
        Buffer.from(a, 'utf8'),
        Buffer.from(b, 'utf8')
      );

    } catch (error) {
      return false;
    }
  }

  /**
   * Get encryption service status and configuration
   */
  getStatus() {
    return {
      algorithm: this.algorithm,
      keyLength: this.keyLength,
      ivLength: this.ivLength,
      tagLength: this.tagLength,
      primaryKeyLoaded: !!this.primaryKey,
      rotationKeyLoaded: !!this.rotationKey,
      keyVersion: this.rotationKey ? 2 : 1
    };
  }
}

// Create singleton instance
const encryptionService = new EncryptionService();

module.exports = encryptionService;