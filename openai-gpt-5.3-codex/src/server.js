import { app } from "./app.js";
import { config } from "./config.js";
import { closeDb, initDb } from "./db.js";

let server = null;

try {
  await initDb();
} catch (error) {
  console.error("Failed to initialize database:", error);
  process.exit(1);
}

server = app.listen(config.port, () => {
  console.log(`Secure notes app listening on port ${config.port}`);
});

function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);
  if (!server) {
    closeDb();
    process.exit(0);
  }
  server.close(() => {
    closeDb();
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});
