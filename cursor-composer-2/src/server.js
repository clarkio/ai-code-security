import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import { initDb } from './db/index.js';
import { createApp } from './app.js';

const dataDir = path.dirname(config.databasePath);
fs.mkdirSync(dataDir, { recursive: true });

initDb();

const app = createApp();

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`Listening on http://127.0.0.1:${config.port} (${config.isProd ? 'production' : 'development'})`);
});
