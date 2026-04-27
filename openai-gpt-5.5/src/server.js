import { createApp } from './app.js';
import { config } from './config.js';

const { app, db } = createApp();
const server = app.listen(config.port, () => {
  console.info(`Secure Notes listening on port ${config.port}`);
});

function shutdown(signal) {
  console.info(`Received ${signal}; shutting down`);
  server.close(() => {
    db.close();
    process.exit(0);
  });

  setTimeout(() => {
    console.error('Timed out during shutdown');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
