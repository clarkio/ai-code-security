import { db } from "./db";
import { auditLogs, type InsertAuditLog } from "@shared/schema";
import type { Request } from "express";

export enum AuditAction {
  // Authentication actions
  LOGIN_SUCCESS = "LOGIN_SUCCESS",
  LOGIN_FAILED = "LOGIN_FAILED",
  LOGOUT = "LOGOUT",
  
  // Note actions
  CREATE_NOTE = "CREATE_NOTE",
  READ_NOTE = "READ_NOTE",
  UPDATE_NOTE = "UPDATE_NOTE",
  DELETE_NOTE = "DELETE_NOTE",
  LIST_NOTES = "LIST_NOTES",
  
  // Security events
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
  XSS_ATTEMPT_BLOCKED = "XSS_ATTEMPT_BLOCKED",
  UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS",
  SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT",
  
  // System events
  USER_CREATED = "USER_CREATED",
  USER_UPDATED = "USER_UPDATED",
}

export enum AuditResource {
  USER = "user",
  NOTE = "note",
  SESSION = "session",
  SYSTEM = "system",
}

export enum AuditSeverity {
  INFO = "info",
  WARNING = "warning", 
  ERROR = "error",
  CRITICAL = "critical",
}

interface AuditContext {
  userId?: string;
  action: AuditAction;
  resource: AuditResource;
  resourceId?: string;
  details?: Record<string, any>;
  severity?: AuditSeverity;
  success?: boolean;
  ipAddress?: string;
  userAgent?: string;
}

class AuditLogger {
  async log(context: AuditContext): Promise<void> {
    try {
      const auditEntry: InsertAuditLog = {
        userId: context.userId || null,
        action: context.action,
        resource: context.resource,
        resourceId: context.resourceId || null,
        details: context.details || null,
        severity: context.severity || AuditSeverity.INFO,
        success: context.success !== false, // Default to true unless explicitly false
        ipAddress: context.ipAddress || null,
        userAgent: context.userAgent || null,
      };

      await db.insert(auditLogs).values(auditEntry);
    } catch (error) {
      // If audit logging fails, we shouldn't break the main application
      // Log to console for monitoring systems to pick up
      console.error("Audit logging failed:", error, context);
    }
  }

  // Helper method to extract request context
  extractRequestContext(req: any): Pick<AuditContext, 'ipAddress' | 'userAgent' | 'userId'> {
    return {
      ipAddress: this.getClientIP(req),
      userAgent: req.get('User-Agent') || undefined,
      userId: req.user?.claims?.sub || undefined,
    };
  }

  private getClientIP(req: Request): string | undefined {
    // Check various headers for the real IP address
    const forwarded = req.get('X-Forwarded-For');
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    
    return req.get('X-Real-IP') || 
           req.get('CF-Connecting-IP') || // Cloudflare
           req.socket.remoteAddress || 
           undefined;
  }

  // Convenience methods for common audit events
  async logAuthEvent(action: AuditAction, req: any, success: boolean = true, details?: Record<string, any>) {
    const context = this.extractRequestContext(req);
    await this.log({
      ...context,
      action,
      resource: AuditResource.SESSION,
      severity: success ? AuditSeverity.INFO : AuditSeverity.WARNING,
      success,
      details,
    });
  }

  async logNoteEvent(action: AuditAction, req: any, noteId?: string, success: boolean = true, details?: Record<string, any>) {
    const context = this.extractRequestContext(req);
    await this.log({
      ...context,
      action,
      resource: AuditResource.NOTE,
      resourceId: noteId,
      success,
      details,
    });
  }

  async logSecurityEvent(action: AuditAction, req: any, severity: AuditSeverity = AuditSeverity.WARNING, details?: Record<string, any>) {
    const context = this.extractRequestContext(req);
    await this.log({
      ...context,
      action,
      resource: AuditResource.SYSTEM,
      severity,
      success: false, // Security events are typically failed attempts
      details,
    });
  }
}

export const auditLogger = new AuditLogger();