const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const config = require('./config/environment');
const { securityHeaders, rateLimiter } = require('./middleware/security');
const { cleanupExpiredTokens, isTokenValid } = require('./lib/auth');
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');

const app = express();

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

securityHeaders(app);

app.use(cors({
  origin: config.env === 'production' ? config.allowedOrigins : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
}));

app.use(rateLimiter);

app.use(express.static(path.join(__dirname, '../public')));

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authRoutes);
app.use('/api/notes', notesRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err.message);

  if (config.env === 'development') {
    res.status(500).json({ error: err.message });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

const server = app.listen(config.port, () => {
  console.log(`Server running on port ${config.port} in ${config.env} mode`);
});

process.on('SIGTERM', () => {
  server.close(() => {
    const { close } = require('./database/init');
    close();
    process.exit(0);
  });
});

module.exports = app;
