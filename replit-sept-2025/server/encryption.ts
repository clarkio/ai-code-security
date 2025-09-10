import crypto from 'crypto';

// Enterprise-grade encryption service for data at rest
class EncryptionService {
  private algorithm = 'aes-256-cbc';
  private iterations = 100000; // OWASP recommended minimum
  private saltLength = 32; // 256-bit salt for key derivation
  private ivLength = 16; // 128-bit initialization vector

  private getEncryptionKey(): string {
    const encryptionKey = process.env.ENCRYPTION_KEY;
    if (!encryptionKey) {
      throw new Error('ENCRYPTION_KEY environment variable is required for data encryption');
    }
    if (encryptionKey.length < 32) {
      throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
    }
    return encryptionKey;
  }

  /**
   * Derives an encryption key from the master key and salt using PBKDF2
   */
  private deriveKey(salt: Buffer): Buffer {
    const masterKey = this.getEncryptionKey();
    return crypto.pbkdf2Sync(masterKey, salt, this.iterations, 32, 'sha256');
  }

  /**
   * Encrypts sensitive data using AES-256-CBC
   * Returns base64-encoded encrypted data with salt and IV
   */
  encrypt(plaintext: string): string {
    try {
      // Generate random salt and IV for each encryption
      const salt = crypto.randomBytes(this.saltLength);
      const iv = crypto.randomBytes(this.ivLength);
      
      // Derive encryption key from master key and salt
      const key = this.deriveKey(salt);
      
      // Create cipher and encrypt
      const cipher = crypto.createCipher(this.algorithm, key);
      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      // Combine salt + iv + encrypted data
      const combined = Buffer.concat([
        salt,
        iv, 
        Buffer.from(encrypted, 'base64')
      ]);
      
      return combined.toString('base64');
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypts data encrypted with the encrypt method
   * Expects base64-encoded data containing salt, IV, and encrypted content
   */
  decrypt(encryptedData: string): string {
    try {
      // Decode the combined data
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract components
      const salt = combined.subarray(0, this.saltLength);
      const iv = combined.subarray(this.saltLength, this.saltLength + this.ivLength);
      const encrypted = combined.subarray(this.saltLength + this.ivLength);
      
      // Derive the same encryption key
      const key = this.deriveKey(salt);
      
      // Create decipher and decrypt
      const decipher = crypto.createDecipher(this.algorithm, key);
      let decrypted = decipher.update(encrypted, undefined, 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Failed to decrypt data - data may be corrupted or key is incorrect');
    }
  }

  /**
   * Generates a secure encryption key for use as ENCRYPTION_KEY environment variable
   * This should only be used during initial setup
   */
  static generateEncryptionKey(): string {
    return crypto.randomBytes(64).toString('hex'); // 512-bit key
  }

  /**
   * Validates that the encryption service is properly configured
   */
  validateConfiguration(): boolean {
    try {
      // Test encryption/decryption cycle
      const testData = 'encryption-test-' + Date.now();
      const encrypted = this.encrypt(testData);
      const decrypted = this.decrypt(encrypted);
      
      return testData === decrypted;
    } catch (error) {
      console.error('Encryption configuration validation failed:', error);
      return false;
    }
  }
}

export const encryptionService = new EncryptionService();

// Validate encryption configuration on startup
if (!encryptionService.validateConfiguration()) {
  console.error('CRITICAL: Encryption service configuration is invalid');
  process.exit(1);
}