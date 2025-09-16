const Joi = require('joi');
require('dotenv').config();

// Environment validation schema
const envSchema = Joi.object({
  // Database
  DATABASE_URL: Joi.string().uri().required(),
  DATABASE_SSL: Joi.boolean().default(true),

  // Encryption
  ENCRYPTION_KEY: Joi.string().base64().min(44).required(), // 256-bit key in base64
  ENCRYPTION_KEY_ROTATION: Joi.string().base64().min(44).optional(),

  // JWT
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRY: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRY: Joi.string().default('7d'),

  // Redis
  REDIS_URL: Joi.string().uri().required(),
  REDIS_PASSWORD: Joi.string().optional(),

  // Security
  BCRYPT_ROUNDS: Joi.number().integer().min(10).max(15)
    .default(12),
  RATE_LIMIT_WINDOW: Joi.number().integer().min(1).default(15),
  RATE_LIMIT_MAX_REQUESTS: Joi.number().integer().min(1).default(5),
  SESSION_TIMEOUT: Joi.number().integer().min(5).default(15),

  // Application
  NODE_ENV: Joi.string().valid('development', 'test', 'production').default('development'),
  PORT: Joi.number().integer().min(1).max(65535)
    .default(3000),
  CORS_ORIGIN: Joi.string().uri().required(),

  // Logging
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  LOG_FILE: Joi.string().default('logs/app.log'),
}).unknown(true);

// Validate environment variables
const { error, value: envVars } = envSchema.validate(process.env);

if (error) {
  throw new Error(`Environment validation error: ${error.message}`);
}

/**
 * Validate environment variables
 * @throws {Error} If validation fails
 */
function validateEnvironment() {
  const { error } = envSchema.validate(process.env);
  if (error) {
    throw new Error(`Environment validation error: ${error.message}`);
  }
}

// Export validated configuration
const config = {
  database: {
    url: envVars.DATABASE_URL,
    ssl: envVars.DATABASE_SSL,
  },
  encryption: {
    key: envVars.ENCRYPTION_KEY,
    rotationKey: envVars.ENCRYPTION_KEY_ROTATION,
  },
  jwt: {
    secret: envVars.JWT_SECRET,
    refreshSecret: envVars.JWT_REFRESH_SECRET,
    expiry: envVars.JWT_EXPIRY,
    refreshExpiry: envVars.JWT_REFRESH_EXPIRY,
  },
  redis: {
    url: envVars.REDIS_URL,
    password: envVars.REDIS_PASSWORD,
  },
  security: {
    bcryptRounds: envVars.BCRYPT_ROUNDS,
    rateLimitWindow: envVars.RATE_LIMIT_WINDOW,
    rateLimitMaxRequests: envVars.RATE_LIMIT_MAX_REQUESTS,
    sessionTimeout: envVars.SESSION_TIMEOUT,
  },
  app: {
    env: envVars.NODE_ENV,
    port: envVars.PORT,
    corsOrigin: envVars.CORS_ORIGIN,
  },
  logging: {
    level: envVars.LOG_LEVEL,
    file: envVars.LOG_FILE,
  },
};

module.exports = {
  ...config,
  validateEnvironment
};
