export class HttpError extends Error {
  public constructor(
    public readonly status: number,
    public readonly publicMessage: string,
    public readonly code: string,
  ) {
    super(publicMessage);
    this.name = 'HttpError';
  }
}

export class DuplicateUserError extends Error {
  public constructor() {
    super('User already exists');
    this.name = 'DuplicateUserError';
  }
}

export class NoteQuotaError extends Error {
  public constructor() {
    super('Note quota reached');
    this.name = 'NoteQuotaError';
  }
}

export function notFound(): HttpError {
  return new HttpError(404, 'The requested page was not found.', 'NOT_FOUND');
}
