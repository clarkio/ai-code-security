import { Router } from "express";
import { ZodError } from "zod";
import { createNote, deleteNote, getNoteById, listNotes, updateNote } from "../db.js";
import {
  createNoteSchema,
  noteIdSchema,
  paginationSchema,
  updateNoteSchema,
} from "../validation.js";

const router = Router();

function validationError(res, error) {
  if (!(error instanceof ZodError)) {
    return res.status(400).json({ error: "Invalid input" });
  }
  return res.status(400).json({
    error: "Invalid input",
    details: error.issues.map((issue) => ({
      path: issue.path.join("."),
      message: issue.message,
    })),
  });
}

router.get("/", (req, res, next) => {
  try {
    const { limit, offset } = paginationSchema.parse(req.query);
    const notes = listNotes(limit, offset);
    return res.json({ notes, limit, offset });
  } catch (error) {
    if (error instanceof ZodError) {
      return validationError(res, error);
    }
    return next(error);
  }
});

router.get("/:id", (req, res, next) => {
  try {
    const id = noteIdSchema.parse(req.params.id);
    const note = getNoteById(id);
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    return res.json({ note });
  } catch (error) {
    if (error instanceof ZodError) {
      return validationError(res, error);
    }
    return next(error);
  }
});

router.post("/", (req, res, next) => {
  try {
    const payload = createNoteSchema.parse(req.body);
    const note = createNote(payload);
    return res.status(201).json({ note });
  } catch (error) {
    if (error instanceof ZodError) {
      return validationError(res, error);
    }
    return next(error);
  }
});

router.put("/:id", (req, res, next) => {
  try {
    const id = noteIdSchema.parse(req.params.id);
    const payload = updateNoteSchema.parse(req.body);
    const note = updateNote(id, payload);
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    return res.json({ note });
  } catch (error) {
    if (error instanceof ZodError) {
      return validationError(res, error);
    }
    return next(error);
  }
});

router.delete("/:id", (req, res, next) => {
  try {
    const id = noteIdSchema.parse(req.params.id);
    const deleted = deleteNote(id);
    if (!deleted) {
      return res.status(404).json({ error: "Note not found" });
    }
    return res.status(204).send();
  } catch (error) {
    if (error instanceof ZodError) {
      return validationError(res, error);
    }
    return next(error);
  }
});

export { router as notesRouter };
