import { z } from 'zod';

export const usernameSchema = z.string()
    .min(3)
    .max(30)
    .regex(/^[a-zA-Z0-9_]+$/);

export const passwordSchema = z.string()
    .min(12)
    .max(200);

export const noteIdSchema = z.coerce.number().int().positive();

export const noteCreateSchema = z.object({
    title: z.string().min(1).max(200),
    body: z.string().max(5000)
});

export const noteUpdateSchema = z.object({
    title: z.string().min(1).max(200),
    body: z.string().max(5000)
});


