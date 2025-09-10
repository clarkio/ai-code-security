import {
  users,
  notes,
  type User,
  type UpsertUser,
  type Note,
  type InsertNote,
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc } from "drizzle-orm";
import { encryptionService } from "./encryption";

// Interface for storage operations
export interface IStorage {
  // User operations
  // (IMPORTANT) these user operations are mandatory for Replit Auth.
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  
  // Note operations with user authorization
  getUserNotes(userId: string): Promise<Note[]>;
  getNote(id: string, userId: string): Promise<Note | undefined>;
  createNote(note: InsertNote, userId: string): Promise<Note>;
  updateNote(id: string, note: InsertNote, userId: string): Promise<Note | undefined>;
  deleteNote(id: string, userId: string): Promise<boolean>;
}

export class DatabaseStorage implements IStorage {
  
  // Encryption/Decryption helpers for sensitive data
  private encryptContent(content: string): string {
    try {
      return encryptionService.encrypt(content);
    } catch (error) {
      console.error('Failed to encrypt note content:', error);
      throw new Error('Failed to encrypt note content');
    }
  }

  private decryptContent(encryptedContent: string): string {
    try {
      return encryptionService.decrypt(encryptedContent);
    } catch (error) {
      console.error('Failed to decrypt note content:', error);
      throw new Error('Failed to decrypt note content');
    }
  }

  // User operations
  // (IMPORTANT) these user operations are mandatory for Replit Auth.

  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.email,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  // Note operations with strict user authorization
  async getUserNotes(userId: string): Promise<Note[]> {
    const encryptedNotes = await db
      .select()
      .from(notes)
      .where(eq(notes.userId, userId))
      .orderBy(desc(notes.updatedAt));
    
    // Decrypt note content before returning
    return encryptedNotes.map(note => ({
      ...note,
      content: this.decryptContent(note.content)
    }));
  }

  async getNote(id: string, userId: string): Promise<Note | undefined> {
    const [note] = await db
      .select()
      .from(notes)
      .where(and(eq(notes.id, id), eq(notes.userId, userId)));
    
    if (!note) return undefined;
    
    // Decrypt content before returning
    return {
      ...note,
      content: this.decryptContent(note.content)
    };
  }

  async createNote(note: InsertNote, userId: string): Promise<Note> {
    const [newNote] = await db
      .insert(notes)
      .values({
        ...note,
        content: this.encryptContent(note.content), // Encrypt content before storing
        userId,
      })
      .returning();
    
    // Return decrypted version to caller
    return {
      ...newNote,
      content: note.content // Return original unencrypted content
    };
  }

  async updateNote(id: string, note: InsertNote, userId: string): Promise<Note | undefined> {
    const [updatedNote] = await db
      .update(notes)
      .set({
        ...note,
        content: this.encryptContent(note.content), // Encrypt content before storing
        updatedAt: new Date(),
      })
      .where(and(eq(notes.id, id), eq(notes.userId, userId)))
      .returning();
    
    if (!updatedNote) return undefined;
    
    // Return decrypted version to caller
    return {
      ...updatedNote,
      content: note.content // Return original unencrypted content
    };
  }

  async deleteNote(id: string, userId: string): Promise<boolean> {
    const result = await db
      .delete(notes)
      .where(and(eq(notes.id, id), eq(notes.userId, userId)));
    return (result.rowCount ?? 0) > 0;
  }
}

export const storage = new DatabaseStorage();
