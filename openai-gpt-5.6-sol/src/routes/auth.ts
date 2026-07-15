import { Router, type Request, type Response } from 'express';
import type { AppConfig } from '../config.js';
import { DuplicateUserError } from '../errors.js';
import { requireAuthentication, requireGuest } from '../middleware/auth.js';
import type { UserRepository } from '../repositories.js';
import { createCsrfProtection, exposeCsrfToken } from '../security/csrf.js';
import { hashPassword, verifyPassword } from '../security/password.js';
import { destroySession, regenerateSession, saveSession } from '../security/session-helpers.js';
import { loginSchema, registerSchema } from '../validation.js';

interface AuthRouterOptions {
  readonly config: AppConfig;
  readonly users: UserRepository;
  readonly authRateLimit: ReturnType<typeof import('express-rate-limit').rateLimit>;
  readonly sessionCookieName: string;
}

function renderLogin(response: Response, status: number, error?: string, email = ''): void {
  response.status(status).render('login', { title: 'Sign in', error, email });
}

function renderRegister(response: Response, status: number, error?: string, email = ''): void {
  response.status(status).render('register', { title: 'Create account', error, email });
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();
  const protectCsrf = createCsrfProtection(
    options.config.publicOrigin,
    !options.config.isProduction,
  );

  router.get('/login', requireGuest, exposeCsrfToken, (_request, response) => {
    renderLogin(response, 200);
  });

  router.post(
    '/login',
    requireGuest,
    options.authRateLimit,
    protectCsrf,
    async (request: Request, response: Response) => {
      const parsed = loginSchema.safeParse(request.body);
      if (!parsed.success) {
        renderLogin(response, 401, 'Email or password is incorrect.');
        return;
      }

      const user = await options.users.findByEmail(parsed.data.email);
      const passwordIsValid = await verifyPassword(user?.passwordHash, parsed.data.password);
      if (user === undefined || !passwordIsValid) {
        renderLogin(response, 401, 'Email or password is incorrect.', parsed.data.email);
        return;
      }

      await regenerateSession(request);
      request.session.userId = user.id;
      request.session.authenticatedAt = Date.now();
      await saveSession(request);
      response.redirect(303, '/notes');
    },
  );

  router.get('/register', requireGuest, exposeCsrfToken, (_request, response) => {
    renderRegister(response, 200);
  });

  router.post(
    '/register',
    requireGuest,
    options.authRateLimit,
    protectCsrf,
    async (request: Request, response: Response) => {
      const parsed = registerSchema.safeParse(request.body);
      if (!parsed.success) {
        renderRegister(
          response,
          400,
          'Use a valid email and a 12–128 character password, entered twice.',
        );
        return;
      }

      const passwordHash = await hashPassword(parsed.data.password);
      try {
        await options.users.create(parsed.data.email, passwordHash);
      } catch (error) {
        if (!(error instanceof DuplicateUserError)) throw error;
      }

      // New and duplicate addresses intentionally receive the same response so
      // registration cannot be used as a reliable account-enumeration oracle.
      request.session.flash = {
        type: 'success',
        message: 'If those details were available, the account is ready. You can sign in.',
      };
      await saveSession(request);
      response.redirect(303, '/login');
    },
  );

  router.post('/logout', requireAuthentication, protectCsrf, async (request, response) => {
    await destroySession(request);
    response.clearCookie(options.sessionCookieName, {
      httpOnly: true,
      secure: options.config.isProduction,
      sameSite: 'strict',
      path: '/',
    });
    response.redirect(303, '/login');
  });

  return router;
}
