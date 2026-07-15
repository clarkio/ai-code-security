import { randomUUID } from 'node:crypto';
import pino, { type Logger } from 'pino';
import { pinoHttp } from 'pino-http';

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: null,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers.set-cookie',
        '*.password',
        '*.passwordConfirm',
        '*.passwordHash',
        '*._csrf',
      ],
      censor: '[REDACTED]',
    },
  });
}

function safePath(rawUrl: string | undefined): string {
  try {
    return new URL(rawUrl ?? '/', 'http://internal.invalid').pathname;
  } catch {
    return '/invalid-url';
  }
}

export function requestLogger(logger: Logger) {
  return pinoHttp({
    logger,
    wrapSerializers: false,
    genReqId(_request, response) {
      const id = randomUUID();
      response.setHeader('X-Request-ID', id);
      return id;
    },
    serializers: {
      req(request) {
        return {
          id: request.id,
          method: request.method,
          path: safePath(request.url),
          remoteAddress: request.socket?.remoteAddress,
        };
      },
      res(response) {
        return { statusCode: response.statusCode };
      },
    },
    customLogLevel(_request, response, error) {
      if (error !== undefined || response.statusCode >= 500) return 'error';
      if (response.statusCode >= 400) return 'warn';
      return 'info';
    },
  });
}
