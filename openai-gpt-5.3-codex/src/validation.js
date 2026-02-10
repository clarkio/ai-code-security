import { z } from "zod";

export const noteIdSchema = z.string().uuid();

const titleSchema = z.string().trim().min(1).max(200);
const contentSchema = z.string().trim().max(5000);

export const createNoteSchema = z
  .object({
    title: titleSchema,
    content: contentSchema.default(""),
  })
  .strict();

export const updateNoteSchema = z
  .object({
    title: titleSchema,
    content: contentSchema,
  })
  .strict();

export const paginationSchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(50),
    offset: z.coerce.number().int().min(0).max(10_000).default(0),
  })
  .strict();
