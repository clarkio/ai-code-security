import './db/init.js';
import { createApp } from './app.js';
import { config } from './config.js';
import { closeDatabase } from './db/database.js';

const app = createApp();

const server = app.listen(config.port, config.host, () => {
  console.log(
    `Secure Notes listening on http://${config.host}:${config.port} (${config.nodeEnv})`
  );
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down...`);
  server.close(() => {
    closeDatabase();
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
