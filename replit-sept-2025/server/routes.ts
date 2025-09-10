import type { Express } from "express";
import { createServer, type Server } from "http";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { insertNoteSchema } from "@shared/schema";
import { z } from "zod";
import DOMPurify from "isomorphic-dompurify";
import { auditLogger, AuditAction, AuditSeverity } from "./auditLogger";

// Rate limiting configuration with audit logging
const createRateLimitWithAudit = (config: any, action: AuditAction) => rateLimit({
  ...config,
  handler: async (req: any, res, next) => {
    // Log rate limit exceeded event
    await auditLogger.logSecurityEvent(action, req, AuditSeverity.WARNING, {
      limit: config.max,
      windowMs: config.windowMs,
      endpoint: req.originalUrl
    });
    res.status(429).json(config.message);
  }
});

const authRateLimit = createRateLimitWithAudit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 attempts per minute
  message: { message: "Too many authentication attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
}, AuditAction.RATE_LIMIT_EXCEEDED);

const apiRateLimit = createRateLimitWithAudit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per IP
  message: { message: "Too many requests. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
}, AuditAction.RATE_LIMIT_EXCEEDED);

const noteOperationRateLimit = createRateLimitWithAudit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 note operations per minute
  message: { message: "Too many note operations. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
}, AuditAction.RATE_LIMIT_EXCEEDED);

// Security sanitization function to prevent XSS attacks
function sanitizeInput(input: string, req?: any): string {
  const original = input;
  const sanitized = DOMPurify.sanitize(input, { 
    ALLOWED_TAGS: [], // No HTML tags allowed
    ALLOWED_ATTR: [], // No attributes allowed
    KEEP_CONTENT: true // Keep text content but strip all HTML
  });
  
  // Check if content was modified (potential XSS attempt)
  if (original !== sanitized && req) {
    auditLogger.logSecurityEvent(AuditAction.XSS_ATTEMPT_BLOCKED, req, AuditSeverity.WARNING, {
      originalLength: original.length,
      sanitizedLength: sanitized.length,
      containedHtml: original.includes('<'),
      containedScript: original.toLowerCase().includes('script')
    });
  }
  
  return sanitized;
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'development' ? false : {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        scriptSrc: ["'self'", "https://replit.com"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "ws:", "wss:", "https://replit.com"],
        workerSrc: ["'self'", "blob:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));

  // Rate limiting
  app.use("/api/login", authRateLimit);
  app.use("/api/logout", authRateLimit);
  app.use("/api", apiRateLimit);

  // Auth middleware
  await setupAuth(app);

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Notes API routes with user authorization
  app.get("/api/notes", isAuthenticated, noteOperationRateLimit, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const userNotes = await storage.getUserNotes(userId);
      
      // Log successful note list retrieval
      await auditLogger.logNoteEvent(AuditAction.LIST_NOTES, req, undefined, true, {
        notesCount: userNotes.length
      });
      
      res.json(userNotes);
    } catch (error) {
      console.error("Error fetching notes:", error);
      
      // Log failed note list retrieval
      await auditLogger.logNoteEvent(AuditAction.LIST_NOTES, req, undefined, false, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      res.status(500).json({ message: "Failed to fetch notes" });
    }
  });

  app.get("/api/notes/:id", isAuthenticated, noteOperationRateLimit, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const noteId = req.params.id;
      
      // Validate note ID format
      if (!noteId || typeof noteId !== 'string') {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Invalid note ID format",
          noteId
        });
        return res.status(400).json({ message: "Invalid note ID" });
      }

      const note = await storage.getNote(noteId, userId);
      if (!note) {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Note not found or access denied",
          noteId
        });
        return res.status(404).json({ message: "Note not found or access denied" });
      }
      
      // Log successful note access
      await auditLogger.logNoteEvent(AuditAction.READ_NOTE, req, noteId, true);
      
      res.json(note);
    } catch (error) {
      console.error("Error fetching note:", error);
      
      // Log failed note access
      await auditLogger.logNoteEvent(AuditAction.READ_NOTE, req, req.params.id, false, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      res.status(500).json({ message: "Failed to fetch note" });
    }
  });

  app.post("/api/notes", isAuthenticated, noteOperationRateLimit, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      
      // Validate input with Zod schema
      const result = insertNoteSchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({ 
          message: "Invalid input", 
          errors: result.error.issues 
        });
      }

      // Sanitize input to prevent XSS attacks
      const sanitizedData = {
        title: sanitizeInput(result.data.title, req),
        content: sanitizeInput(result.data.content, req)
      };

      const newNote = await storage.createNote(sanitizedData, userId);
      
      // Log successful note creation
      await auditLogger.logNoteEvent(AuditAction.CREATE_NOTE, req, newNote.id, true, {
        title: newNote.title,
        contentLength: newNote.content.length
      });
      
      res.status(201).json(newNote);
    } catch (error) {
      console.error("Error creating note:", error);
      
      // Log failed note creation
      await auditLogger.logNoteEvent(AuditAction.CREATE_NOTE, req, undefined, false, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      res.status(500).json({ message: "Failed to create note" });
    }
  });

  app.put("/api/notes/:id", isAuthenticated, noteOperationRateLimit, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const noteId = req.params.id;
      
      // Validate note ID format
      if (!noteId || typeof noteId !== 'string') {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Invalid note ID format for update",
          noteId
        });
        return res.status(400).json({ message: "Invalid note ID" });
      }

      // Validate input with Zod schema
      const result = insertNoteSchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({ 
          message: "Invalid input", 
          errors: result.error.issues 
        });
      }

      // Sanitize input to prevent XSS attacks  
      const sanitizedData = {
        title: sanitizeInput(result.data.title, req),
        content: sanitizeInput(result.data.content, req)
      };

      const updatedNote = await storage.updateNote(noteId, sanitizedData, userId);
      if (!updatedNote) {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Note not found or access denied for update",
          noteId
        });
        return res.status(404).json({ message: "Note not found or access denied" });
      }
      
      // Log successful note update
      await auditLogger.logNoteEvent(AuditAction.UPDATE_NOTE, req, noteId, true, {
        title: updatedNote.title,
        contentLength: updatedNote.content.length
      });
      
      res.json(updatedNote);
    } catch (error) {
      console.error("Error updating note:", error);
      
      // Log failed note update
      await auditLogger.logNoteEvent(AuditAction.UPDATE_NOTE, req, req.params.id, false, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      res.status(500).json({ message: "Failed to update note" });
    }
  });

  app.delete("/api/notes/:id", isAuthenticated, noteOperationRateLimit, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const noteId = req.params.id;
      
      // Validate note ID format
      if (!noteId || typeof noteId !== 'string') {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Invalid note ID format for deletion",
          noteId
        });
        return res.status(400).json({ message: "Invalid note ID" });
      }

      const deleted = await storage.deleteNote(noteId, userId);
      if (!deleted) {
        await auditLogger.logSecurityEvent(AuditAction.UNAUTHORIZED_ACCESS, req, AuditSeverity.WARNING, {
          reason: "Note not found or access denied for deletion",
          noteId
        });
        return res.status(404).json({ message: "Note not found or access denied" });
      }
      
      // Log successful note deletion
      await auditLogger.logNoteEvent(AuditAction.DELETE_NOTE, req, noteId, true);
      res.json({ message: "Note deleted successfully" });
    } catch (error) {
      console.error("Error deleting note:", error);
      
      // Log failed note deletion
      await auditLogger.logNoteEvent(AuditAction.DELETE_NOTE, req, req.params.id, false, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      res.status(500).json({ message: "Failed to delete note" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
