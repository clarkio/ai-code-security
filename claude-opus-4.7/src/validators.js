'use strict';

const { z } = require('zod');
const config = require('./config');

const usernameSchema = z
  .string()
  .trim()
  .min(config.limits.usernameMin)
  .max(config.limits.usernameMax)
  // Restrict to a safe charset; prevents homoglyph/unicode confusables and
  // keeps usernames suitable for display without further normalization.
  .regex(/^[a-zA-Z0-9_.-]+$/, 'Username may contain letters, digits, "_", ".", "-" only');

const passwordSchema = z
  .string()
  .min(config.limits.passwordMin)
  .max(config.limits.passwordMax);

const credentialsSchema = z.object({
  username: usernameSchema,
  password: passwordSchema,
});

const noteSchema = z.object({
  title: z.string().trim().min(1).max(config.limits.noteTitleMax),
  body: z.string().max(config.limits.noteBodyMax).default(''),
});

const idSchema = z.coerce.number().int().positive().max(2_147_483_647);

module.exports = {
  credentialsSchema,
  noteSchema,
  idSchema,
};
