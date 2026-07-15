import { randomUUID } from 'node:crypto';
import { DuplicateUserError } from '../../src/errors.js';
import type {
  NoteRecord,
  NoteRepository,
  UpdateResult,
  UserRecord,
  UserRepository,
} from '../../src/repositories.js';
import type { CreateNoteInput, UpdateNoteInput } from '../../src/validation.js';

function copyUser(user: UserRecord): UserRecord {
  return { ...user };
}

export class FakeUserRepository implements UserRepository {
  readonly #usersByEmail = new Map<string, UserRecord>();

  public seed(email: string, passwordHash: string, id = randomUUID()): UserRecord {
    const user = { id, email, passwordHash };
    this.#usersByEmail.set(email, user);
    return copyUser(user);
  }

  public async findByEmail(email: string): Promise<UserRecord | undefined> {
    const user = this.#usersByEmail.get(email);
    return user === undefined ? undefined : copyUser(user);
  }

  public async create(email: string, passwordHash: string): Promise<UserRecord> {
    if (this.#usersByEmail.has(email)) throw new DuplicateUserError();
    return this.seed(email, passwordHash);
  }
}

interface OwnedNote extends NoteRecord {
  readonly userId: string;
}

function publicNote(note: OwnedNote): NoteRecord {
  return {
    id: note.id,
    title: note.title,
    content: note.content,
    version: note.version,
    createdAt: new Date(note.createdAt),
    updatedAt: new Date(note.updatedAt),
  };
}

export class FakeNoteRepository implements NoteRepository {
  readonly #notesById = new Map<string, OwnedNote>();
  #listFailure: Error | undefined;

  public seed(
    userId: string,
    input: { readonly title: string; readonly content: string },
    id = randomUUID(),
  ): NoteRecord {
    const now = new Date('2026-01-02T03:04:05.000Z');
    const note: OwnedNote = {
      id,
      userId,
      title: input.title,
      content: input.content,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    this.#notesById.set(id, note);
    return publicNote(note);
  }

  public failListWith(error: Error): void {
    this.#listFailure = error;
  }

  public async list(userId: string): Promise<readonly NoteRecord[]> {
    if (this.#listFailure !== undefined) throw this.#listFailure;
    return [...this.#notesById.values()]
      .filter((note) => note.userId === userId)
      .map(publicNote);
  }

  public async find(userId: string, noteId: string): Promise<NoteRecord | undefined> {
    const note = this.#notesById.get(noteId);
    return note === undefined || note.userId !== userId ? undefined : publicNote(note);
  }

  public async create(userId: string, input: CreateNoteInput): Promise<NoteRecord> {
    return this.seed(userId, input);
  }

  public async update(
    userId: string,
    noteId: string,
    input: UpdateNoteInput,
  ): Promise<UpdateResult> {
    const note = this.#notesById.get(noteId);
    if (note === undefined || note.userId !== userId) return 'not_found';
    if (note.version !== input.version) return 'conflict';

    this.#notesById.set(noteId, {
      ...note,
      title: input.title,
      content: input.content,
      version: note.version + 1,
      updatedAt: new Date('2026-01-02T03:05:05.000Z'),
    });
    return 'updated';
  }

  public async delete(userId: string, noteId: string): Promise<boolean> {
    const note = this.#notesById.get(noteId);
    if (note === undefined || note.userId !== userId) return false;
    return this.#notesById.delete(noteId);
  }
}
