const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;
const NOTES_FILE = path.join(__dirname, 'notes.json');

let notes = [];
function loadNotes() {
  try {
    const data = fs.readFileSync(NOTES_FILE, 'utf8');
    notes = JSON.parse(data);
  } catch (e) {
    notes = [];
  }
}
function saveNotes() {
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes, null, 2), 'utf8');
}
function sanitize(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 100;
const rateMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  if (!rateMap.has(ip)) {
    rateMap.set(ip, { count: 1, start: now });
    return false;
  }
  const info = rateMap.get(ip);
  if (now - info.start > RATE_LIMIT_WINDOW) {
    rateMap.set(ip, { count: 1, start: now });
    return false;
  }
  info.count += 1;
  if (info.count > RATE_LIMIT_MAX) {
    return true;
  }
  return false;
}

loadNotes();

function sendJSON(res, status, obj) {
  const data = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'"
  });
  res.end(data);
}

function serveStatic(res, pathname) {
  const filePath = path.join(__dirname, 'public', pathname);
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    sendJSON(res, 400, { error: 'Invalid path' });
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not Found');
    }
    const ext = path.extname(filePath);
    const mime = ext === '.js' ? 'application/javascript' : ext === '.css' ? 'text/css' : 'text/html';
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': data.length,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Security-Policy': "default-src 'self'"
    });
    res.end(data);
  });
}

function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => {
    body += chunk;
    if (body.length > 1e6) req.destroy();
  });
  req.on('end', () => {
    try {
      const data = JSON.parse(body || '{}');
      callback(null, data);
    } catch (e) {
      callback(e);
    }
  });
}

const server = http.createServer((req, res) => {
  const ip = req.socket.remoteAddress || '';
  if (isRateLimited(ip)) {
    return sendJSON(res, 429, { error: 'Too many requests' });
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (req.method === 'GET' && pathname === '/') {
    return serveStatic(res, 'index.html');
  }
  if (req.method === 'GET' && pathname.startsWith('/static/')) {
    return serveStatic(res, pathname.slice(8));
  }

  if (pathname === '/api/notes') {
    if (req.method === 'GET') {
      return sendJSON(res, 200, notes);
    }
    if (req.method === 'POST') {
      return parseBody(req, (err, data) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
        const title = sanitize(data.title).trim();
        const content = sanitize(data.content).trim();
        if (!title || !content || title.length > 100 || content.length > 1000) {
          return sendJSON(res, 400, { error: 'Invalid input' });
        }
        const id = Date.now().toString();
        const note = { id, title, content, createdAt: new Date().toISOString() };
        notes.push(note);
        saveNotes();
        sendJSON(res, 201, note);
      });
    }
  }

  if (pathname.startsWith('/api/notes/')) {
    const id = pathname.slice('/api/notes/'.length);
    const noteIndex = notes.findIndex(n => n.id === id);
    if (noteIndex === -1) {
      return sendJSON(res, 404, { error: 'Not found' });
    }
    if (req.method === 'PUT') {
      return parseBody(req, (err, data) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid JSON' });
        const title = sanitize(data.title).trim();
        const content = sanitize(data.content).trim();
        if (!title || !content || title.length > 100 || content.length > 1000) {
          return sendJSON(res, 400, { error: 'Invalid input' });
        }
        notes[noteIndex].title = title;
        notes[noteIndex].content = content;
        notes[noteIndex].updatedAt = new Date().toISOString();
        saveNotes();
        sendJSON(res, 200, notes[noteIndex]);
      });
    }
    if (req.method === 'DELETE') {
      const note = notes.splice(noteIndex, 1)[0];
      saveNotes();
      return sendJSON(res, 200, note);
    }
  }

  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
