'use strict';

const { z } = require('zod');

// Strict, allow-list-style validation. Anything that doesn't match these
// schemas is rejected before it reaches business logic or the database.

const username = z
  .string()
  .trim()
  .min(3, 'Username must be at least 3 characters.')
  .max(32, 'Username must be at most 32 characters.')
  .regex(
    /^[a-zA-Z0-9_]+$/,
    'Username may only contain letters, numbers, and underscores.'
  );

// Follows current NIST guidance: enforce a generous minimum length rather than
// complex composition rules. Cap the maximum to avoid bcrypt's 72-byte truncation
// surprises and to bound work.
const password = z
  .string()
  .min(12, 'Password must be at least 12 characters.')
  .max(72, 'Password must be at most 72 characters.');

const registerSchema = z.object({ username, password });

const loginSchema = z.object({
  username: z.string().trim().min(1).max(32),
  password: z.string().min(1).max(72),
});

const noteSchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, 'Title is required.')
    .max(200, 'Title must be at most 200 characters.'),
  content: z
    .string()
    .max(10000, 'Content must be at most 10,000 characters.')
    .default(''),
});

// Note ids come from the URL. Coerce to a positive integer or reject.
const noteIdSchema = z.coerce.number().int().positive();

module.exports = { registerSchema, loginSchema, noteSchema, noteIdSchema };
