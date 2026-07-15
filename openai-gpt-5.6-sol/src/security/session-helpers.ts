import type { Request } from 'express';

export function regenerateSession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.regenerate((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

export function saveSession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.save((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

export function destroySession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.destroy((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
