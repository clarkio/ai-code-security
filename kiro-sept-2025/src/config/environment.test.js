const config = require('./environment');

describe('Environment Configuration', () => {
  test('should load configuration without errors', () => {
    expect(config).toBeDefined();
    expect(config.app).toBeDefined();
    expect(config.security).toBeDefined();
    expect(config.logging).toBeDefined();
  });

  test('should have required security settings', () => {
    expect(config.security.bcryptRounds).toBeGreaterThanOrEqual(10);
    expect(config.security.rateLimitWindow).toBeGreaterThan(0);
    expect(config.security.rateLimitMaxRequests).toBeGreaterThan(0);
  });

  test('should have valid encryption configuration', () => {
    expect(config.encryption.key).toBeDefined();
    console.log(config.encryption.key.length);
    expect(config.encryption.key.length).toBeGreaterThanOrEqual(44);
  });

  test('should have valid port configuration', () => {
    expect(config.app.port).toBeGreaterThan(0);
    expect(config.app.port).toBeLessThanOrEqual(65535);
  });

  test('should have valid environment setting', () => {
    expect(['development', 'test', 'production']).toContain(config.app.env);
  });
});
