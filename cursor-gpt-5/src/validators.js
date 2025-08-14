const { z } = require('zod');

const emailSchema = z.string().email().max(254);
const passwordSchema = z.string().min(12).max(128);
const titleSchema = z.string().min(1).max(200);
const contentSchema = z.string().min(1).max(5000);

const registerSchema = z.object({
    email: emailSchema,
    password: passwordSchema,
});

const loginSchema = z.object({
    email: emailSchema,
    password: z.string().min(1).max(128),
});

const noteCreateSchema = z.object({
    title: titleSchema,
    content: contentSchema,
});

const noteUpdateSchema = z.object({
    id: z.coerce.number().int().positive(),
    title: titleSchema,
    content: contentSchema,
});

module.exports = {
    registerSchema,
    loginSchema,
    noteCreateSchema,
    noteUpdateSchema,
};


