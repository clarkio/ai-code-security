import { z } from 'zod';
import { config } from '../config.js';

const usernameSchema = z
  .string()
  .trim()
  .min(config.usernameMinLength)
  .max(config.usernameMaxLength)
  .regex(
    /^[a-zA-Z0-9_-]+$/,
    'Username may only contain letters, numbers, underscores, and hyphens'
  );

const passwordSchema = z
  .string()
  .min(config.passwordMinLength)
  .max(config.passwordMaxLength);

export const registerSchema = z.object({
  username: usernameSchema,
  password: passwordSchema,
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export const loginSchema = z.object({
  username: usernameSchema,
  password: z.string().min(1).max(config.passwordMaxLength),
});

export const noteSchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, 'Title is required')
    .max(config.noteTitleMaxLength),
  body: z
    .string()
    .trim()
    .max(config.noteBodyMaxLength)
    .optional()
    .default(''),
});

export const noteIdParamSchema = z.object({
  id: z.coerce.number().int().positive(),
});
