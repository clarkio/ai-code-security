import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type pg from 'pg';
import { createApp } from './app.js';
import { parseConfig, type AppConfig } from './config.js';
import { createPool, databaseIsReady } from './db.js';
import { createLogger } from './logger.js';

export interface RunningApplication {
  readonly server: Server;
  readonly pool: pg.Pool;
  close(): Promise<void>;
}

export async function startServer(config: AppConfig = parseConfig()): Promise<RunningApplication> {
  const logger = createLogger(config.logLevel);
  const pool = createPool(config);
  pool.on('error', (error) => {
    logger.error({ errorType: error.name }, 'Unexpected idle database client error');
  });
  let server: Server;
  try {
    const ready = await databaseIsReady(pool);
    if (!ready) throw new Error('Database schema is not ready; run migrations first');
    const app = createApp({ config, pool, logger });
    server = createServer(app);

    server.requestTimeout = 15_000;
    server.headersTimeout = 10_000;
    server.keepAliveTimeout = 5_000;
    server.maxRequestsPerSocket = 1000;

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, () => {
        server.off('error', reject);
        resolve();
      });
    });
  } catch (error) {
    await pool.end().catch(() => undefined);
    throw error;
  }

  logger.info({ host: config.host, port: config.port }, 'Server started');

  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closePromise ??= (async () => {
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          server.closeAllConnections();
          resolve();
        }, config.shutdownTimeoutMs);
        timeout.unref();
        server.close(() => {
          clearTimeout(timeout);
          resolve();
        });
        server.closeIdleConnections();
      });
      await pool.end();
    })();
    return closePromise;
  };

  return { server, pool, close };
}

async function main(): Promise<void> {
  const running = await startServer();
  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write(`Received ${signal}; shutting down.\n`);
    running
      .close()
      .then(() => {
        process.exitCode = 0;
      })
      .catch(() => {
        process.exitCode = 1;
      });
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(path.resolve(invokedPath)).href) {
  main().catch((error: unknown) => {
    const kind = error instanceof Error ? error.name : 'UnknownError';
    process.stderr.write(`Startup failed (${kind}).\n`);
    process.exitCode = 1;
  });
}
