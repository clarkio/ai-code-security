import 'express-serve-static-core';
import type { IronSession } from 'iron-session';

type SessionUser = {
  id: string;
  email: string;
};

declare module 'express-serve-static-core' {
  interface Request {
    session: IronSession<{
      user?: SessionUser;
      csrfSid?: string;
    }>;
  }
}
