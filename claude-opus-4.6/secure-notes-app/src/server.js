require('dotenv').config();

// Validate required environment variables at startup
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING') {
  console.error(
    'FATAL: SESSION_SECRET is not set or is still the default placeholder.\n' +
    'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"\n' +
    'Then set it in your .env file.'
  );
  process.exit(1);
}

const { initDatabase } = require('./database');
const createApp = require('./app');

const PORT = parseInt(process.env.PORT, 10) || 3000;

async function main() {
  await initDatabase();

  const app = createApp();

  app.listen(PORT, () => {
    console.log(`Secure Notes running on http://localhost:${PORT}`);
    if (process.env.NODE_ENV !== 'production') {
      console.log('WARNING: Running in development mode. Set NODE_ENV=production for deployment.');
    }
  });
}

main().catch((err) => {
  console.error('FATAL: Failed to start server:', err);
  process.exit(1);
});
