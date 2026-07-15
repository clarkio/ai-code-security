import 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    authenticatedAt?: number;
    csrfToken?: string;
    flash?: {
      type: 'success' | 'error';
      message: string;
    };
  }
}
