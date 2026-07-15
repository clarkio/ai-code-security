import { z } from 'zod';

const email = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.email().max(254));

const password = z
  .string()
  .refine((value) => [...value].length >= 12 && [...value].length <= 128)
  .refine((value) => Buffer.byteLength(value, 'utf8') <= 256);

export const registerSchema = z
  .strictObject({
    email,
    password,
    passwordConfirm: z.string(),
  })
  .refine((value) => value.password === value.passwordConfirm, {
    path: ['passwordConfirm'],
  });

export const loginSchema = z.strictObject({
  email,
  password: z
    .string()
    .refine((value) => [...value].length >= 1 && [...value].length <= 128)
    .refine((value) => Buffer.byteLength(value, 'utf8') <= 256),
});

const title = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .refine((value) => !value.includes('\0') && !/[\r\n]/u.test(value));

const content = z
  .string()
  .max(10_000)
  .refine(
    (value) =>
      value.trim().length > 0 &&
      !value.includes('\0') &&
      Buffer.byteLength(value, 'utf8') <= 10_000,
  );

export const createNoteSchema = z.strictObject({ title, content });

export const updateNoteSchema = z.strictObject({
  title,
  content,
  version: z.coerce.number().int().min(1).max(2_147_483_647),
});

export const noteIdSchema = z.uuid();

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type CreateNoteInput = z.infer<typeof createNoteSchema>;
export type UpdateNoteInput = z.infer<typeof updateNoteSchema>;
