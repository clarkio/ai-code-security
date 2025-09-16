const crypto = require('crypto');
const encryptionService = require('./encryptionService');

// Mock the config and logger
jest.mock('../config/environment', () => ({
  encryption: {
    key: Buffer.from('a'.repeat(32), 'utf8').toString('base64'), // 32 bytes = 256 bits
    rotationKey: Buffer.from('b'.repeat(32), 'utf8').toString('base64') // 32 bytes = 256 bits
  }
}));

jest.mock('../utils/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn()
}));

describe('EncryptionService', () => {
  const testPlaintext = 'This is a test message for encryption';
  const testPlaintextLong = 'A'.repeat(10000); // Test with long content
  
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Key Management', () => {
    test('should load encryption keys from environment', () => {
      const status = encryptionService.getStatus();
      
      expect(status.primaryKeyLoaded).toBe(true);
      expect(status.rotationKeyLoaded).toBe(true);
      expect(status.algorithm).toBe('aes-256-gcm');
      expect(status.keyLength).toBe(32);
      expect(status.ivLength).toBe(16);
      expect(status.tagLength).toBe(16);
    });

    test('should generate valid encryption keys', () => {
      const key = encryptionService.constructor.generateKey();
      
      expect(typeof key).toBe('string');
      
      // Decode and check length
      const keyBuffer = Buffer.from(key, 'base64');
      expect(keyBuffer.length).toBe(32); // 256 bits
    });

    test('should handle invalid key format', () => {
      // This would be tested with a separate instance, but for now we test the concept
      expect(() => {
        encryptionService.loadKey('invalid-key');
      }).toThrow('Invalid encryption key configuration');
    });

    test('should handle missing key', () => {
      expect(() => {
        encryptionService.loadKey(null);
      }).toThrow('Invalid encryption key configuration');
    });
  });

  describe('Encryption Operations', () => {
    test('should encrypt plaintext successfully', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(testPlaintext);
      
      // Parse and validate structure
      const data = JSON.parse(encrypted);
      expect(data).toHaveProperty('iv');
      expect(data).toHaveProperty('tag');
      expect(data).toHaveProperty('encrypted');
      expect(data).toHaveProperty('keyVersion');
      expect(data.keyVersion).toBe(1);
      
      // Validate hex format and lengths
      expect(data.iv).toMatch(/^[0-9a-f]{32}$/); // 16 bytes = 32 hex chars
      expect(data.tag).toMatch(/^[0-9a-f]{32}$/); // 16 bytes = 32 hex chars
      expect(data.encrypted).toMatch(/^[0-9a-f]+$/);
    });

    test('should generate unique IVs for each encryption', () => {
      const encrypted1 = encryptionService.encrypt(testPlaintext);
      const encrypted2 = encryptionService.encrypt(testPlaintext);
      
      const data1 = JSON.parse(encrypted1);
      const data2 = JSON.parse(encrypted2);
      
      expect(data1.iv).not.toBe(data2.iv);
      expect(data1.encrypted).not.toBe(data2.encrypted);
    });

    test('should encrypt long content successfully', () => {
      const encrypted = encryptionService.encrypt(testPlaintextLong);
      
      expect(typeof encrypted).toBe('string');
      const data = JSON.parse(encrypted);
      expect(data).toHaveProperty('encrypted');
      expect(data.encrypted.length).toBeGreaterThan(0);
    });

    test('should handle empty plaintext', () => {
      expect(() => {
        encryptionService.encrypt('');
      }).toThrow('Plaintext must be a non-empty string');
    });

    test('should handle null plaintext', () => {
      expect(() => {
        encryptionService.encrypt(null);
      }).toThrow('Plaintext must be a non-empty string');
    });

    test('should handle non-string plaintext', () => {
      expect(() => {
        encryptionService.encrypt(123);
      }).toThrow('Plaintext must be a non-empty string');
    });
  });

  describe('Decryption Operations', () => {
    test('should decrypt encrypted data successfully', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      const decrypted = encryptionService.decrypt(encrypted);
      
      expect(decrypted).toBe(testPlaintext);
    });

    test('should decrypt long content successfully', () => {
      const encrypted = encryptionService.encrypt(testPlaintextLong);
      const decrypted = encryptionService.decrypt(encrypted);
      
      expect(decrypted).toBe(testPlaintextLong);
    });

    test('should handle invalid encrypted data format', () => {
      expect(() => {
        encryptionService.decrypt('invalid-json');
      }).toThrow('Decryption operation failed');
    });

    test('should handle missing encrypted data properties', () => {
      const invalidData = JSON.stringify({
        iv: 'test',
        // missing tag and encrypted
      });
      
      expect(() => {
        encryptionService.decrypt(invalidData);
      }).toThrow('Invalid encrypted data format');
    });

    test('should handle empty encrypted data', () => {
      expect(() => {
        encryptionService.decrypt('');
      }).toThrow('Encrypted data must be a non-empty string');
    });

    test('should handle null encrypted data', () => {
      expect(() => {
        encryptionService.decrypt(null);
      }).toThrow('Encrypted data must be a non-empty string');
    });

    test('should handle tampered encrypted data', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      const data = JSON.parse(encrypted);
      
      // Tamper with the encrypted content
      data.encrypted = data.encrypted.slice(0, -2) + 'ff';
      const tamperedData = JSON.stringify(data);
      
      expect(() => {
        encryptionService.decrypt(tamperedData);
      }).toThrow('Decryption operation failed');
    });

    test('should handle tampered authentication tag', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      const data = JSON.parse(encrypted);
      
      // Tamper with the authentication tag
      data.tag = data.tag.slice(0, -2) + 'ff';
      const tamperedData = JSON.stringify(data);
      
      expect(() => {
        encryptionService.decrypt(tamperedData);
      }).toThrow('Decryption operation failed');
    });
  });

  describe('Key Rotation', () => {
    test('should encrypt with rotation key', () => {
      const encrypted = encryptionService.encryptWithRotationKey(testPlaintext);
      
      expect(typeof encrypted).toBe('string');
      const data = JSON.parse(encrypted);
      expect(data.keyVersion).toBe(2);
    });

    test('should decrypt data encrypted with rotation key', () => {
      const encrypted = encryptionService.encryptWithRotationKey(testPlaintext);
      const decrypted = encryptionService.decrypt(encrypted);
      
      expect(decrypted).toBe(testPlaintext);
    });

    test('should re-encrypt data with rotation key', () => {
      const originalEncrypted = encryptionService.encrypt(testPlaintext);
      const reencrypted = encryptionService.reencrypt(originalEncrypted);
      
      expect(reencrypted).not.toBe(originalEncrypted);
      
      const originalData = JSON.parse(originalEncrypted);
      const reencryptedData = JSON.parse(reencrypted);
      
      expect(originalData.keyVersion).toBe(1);
      expect(reencryptedData.keyVersion).toBe(2);
      
      // Both should decrypt to the same plaintext
      const decrypted1 = encryptionService.decrypt(originalEncrypted);
      const decrypted2 = encryptionService.decrypt(reencrypted);
      
      expect(decrypted1).toBe(testPlaintext);
      expect(decrypted2).toBe(testPlaintext);
    });

    test('should handle key rotation process', () => {
      const result = encryptionService.rotateKeys();
      
      expect(result.success).toBe(true);
      expect(result.newKeyVersion).toBe(2);
      expect(result.message).toBe('Key rotation completed successfully');
      
      const status = encryptionService.getStatus();
      expect(status.rotationKeyLoaded).toBe(false);
    });
  });

  describe('Utility Functions', () => {
    test('should hash data correctly', () => {
      const hash1 = encryptionService.hash(testPlaintext);
      const hash2 = encryptionService.hash(testPlaintext);
      
      expect(typeof hash1).toBe('string');
      expect(hash1).toBe(hash2); // Same input should produce same hash
      expect(hash1).toMatch(/^[0-9a-f]{64}$/); // SHA-256 produces 64 hex chars
    });

    test('should produce different hashes for different inputs', () => {
      const hash1 = encryptionService.hash('input1');
      const hash2 = encryptionService.hash('input2');
      
      expect(hash1).not.toBe(hash2);
    });

    test('should create HMAC correctly', () => {
      const hmac1 = encryptionService.createHMAC(testPlaintext);
      const hmac2 = encryptionService.createHMAC(testPlaintext);
      
      expect(typeof hmac1).toBe('string');
      expect(hmac1).toBe(hmac2); // Same input should produce same HMAC
      expect(hmac1).toMatch(/^[0-9a-f]{64}$/); // HMAC-SHA256 produces 64 hex chars
    });

    test('should verify HMAC correctly', () => {
      const hmac = encryptionService.createHMAC(testPlaintext);
      
      expect(encryptionService.verifyHMAC(testPlaintext, hmac)).toBe(true);
      expect(encryptionService.verifyHMAC('different text', hmac)).toBe(false);
      expect(encryptionService.verifyHMAC(testPlaintext, 'invalid-hmac')).toBe(false);
    });

    test('should perform timing-safe string comparison', () => {
      const str1 = 'test-string';
      const str2 = 'test-string';
      const str3 = 'different-string';
      
      expect(encryptionService.constructor.timingSafeEqual(str1, str2)).toBe(true);
      expect(encryptionService.constructor.timingSafeEqual(str1, str3)).toBe(false);
      expect(encryptionService.constructor.timingSafeEqual(str1, null)).toBe(false);
      expect(encryptionService.constructor.timingSafeEqual(null, str2)).toBe(false);
    });
  });

  describe('Error Handling', () => {
    test('should handle hash function errors gracefully', () => {
      expect(() => {
        encryptionService.hash(null);
      }).toThrow('Hashing operation failed');
    });

    test('should handle HMAC creation errors gracefully', () => {
      expect(() => {
        encryptionService.createHMAC(null);
      }).toThrow('HMAC creation failed');
    });

    test('should handle HMAC verification errors gracefully', () => {
      const result = encryptionService.verifyHMAC(null, 'test');
      expect(result).toBe(false);
    });

    test('should handle encryption with rotation key when key not available', () => {
      // Temporarily remove rotation key to test error handling
      const originalRotationKey = encryptionService.rotationKey;
      encryptionService.rotationKey = null;
      
      expect(() => {
        encryptionService.encryptWithRotationKey(testPlaintext);
      }).toThrow('Rotation key encryption operation failed');
      
      // Restore rotation key
      encryptionService.rotationKey = originalRotationKey;
    });
  });

  describe('Security Properties', () => {
    test('should use different IVs for identical plaintexts', () => {
      const encrypted1 = encryptionService.encrypt(testPlaintext);
      const encrypted2 = encryptionService.encrypt(testPlaintext);
      
      const data1 = JSON.parse(encrypted1);
      const data2 = JSON.parse(encrypted2);
      
      expect(data1.iv).not.toBe(data2.iv);
      expect(data1.encrypted).not.toBe(data2.encrypted);
    });

    test('should detect tampering with authentication tag', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      const data = JSON.parse(encrypted);
      
      // Flip a bit in the authentication tag
      const tagBuffer = Buffer.from(data.tag, 'hex');
      tagBuffer[0] = tagBuffer[0] ^ 1;
      data.tag = tagBuffer.toString('hex');
      
      const tamperedData = JSON.stringify(data);
      
      expect(() => {
        encryptionService.decrypt(tamperedData);
      }).toThrow('Decryption operation failed');
    });

    test('should detect tampering with IV', () => {
      const encrypted = encryptionService.encrypt(testPlaintext);
      const data = JSON.parse(encrypted);
      
      // Flip a bit in the IV
      const ivBuffer = Buffer.from(data.iv, 'hex');
      ivBuffer[0] = ivBuffer[0] ^ 1;
      data.iv = ivBuffer.toString('hex');
      
      const tamperedData = JSON.stringify(data);
      
      expect(() => {
        encryptionService.decrypt(tamperedData);
      }).toThrow('Decryption operation failed');
    });

    test('should use proper key lengths', () => {
      const status = encryptionService.getStatus();
      
      expect(status.keyLength).toBe(32); // 256 bits
      expect(status.ivLength).toBe(16); // 128 bits
      expect(status.tagLength).toBe(16); // 128 bits
    });
  });
});