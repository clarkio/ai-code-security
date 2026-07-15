import { parseConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { startServer } from '../src/server.js';
import { runMigrations } from './migrate.js';

async function main(): Promise<void> {
  const config = parseConfig();
  const migrationPool = createPool(config);
  try {
    await runMigrations(migrationPool);
  } finally {
    await migrationPool.end();
  }

  const running = await startServer(config);
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

main().catch((error: unknown) => {
  const kind = error instanceof Error ? error.name : 'UnknownError';
  process.stderr.write(`Startup failed (${kind}).\n`);
  process.exitCode = 1;
});
