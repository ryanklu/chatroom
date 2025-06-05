// server.js
const express = require('express');
const http = require('http');
const sqlite3 = require('sqlite3');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');

const CHAT_PASSWORD = 'rancho3'; // CHANGE THIS PASSWORD!
const JWT_SECRET = 'rancho3'; // Change this as well!

function createJWT(username) {
  // Super simple token: (username + timestamp + secret hash)
  // Not for production! For demo only.
  const payload = `${username}|${Date.now()}`;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}|${signature}`).toString('base64');
}
function verifyJWT(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString();
    const parts = decoded.split('|');
    const signature = parts.pop();
    const payload = parts.join('|');
    const calcSig = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    if(signature === calcSig) return parts[0];
    return null;
  } catch { return null; }
}

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// DB setup
const db = new sqlite3.Database('./chatdb.sqlite');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender TEXT,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Middleware
app.use(express.json());
app.use(express.static(__dirname));

// Login endpoint
app.post('/login', (req, res) => {
  let { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  username = username.replace(/[^\w.-]/g, '').slice(0, 24); // simple sanitization
  if (password !== CHAT_PASSWORD)
    return res.status(401).json({ error: 'Wrong password.' });
  const token = createJWT(username);
  res.json({ token });
});

// Auth middleware
function auth(req, res, next) {
  let auth = req.headers.authorization;
  if (!auth) return res.status(403).json({ error: "Missing credentials" });
  if (auth.startsWith('Bearer ')) auth = auth.slice(7);
  const user = verifyJWT(auth);
  if(!user) return res.status(401).json({ error: 'Invalid session' });
  req.username = user;
  next();
}

// Get messages
app.get('/messages', auth, (req, res) => {
  db.all('SELECT sender, message, timestamp FROM messages ORDER BY id ASC', [], (err, rows) => {
    if(err) return res.status(500).json({error: 'DB error'});
    res.json(rows);
  });
});

// Socket.io authentication
io.use((socket, next) => {
  let auth = socket.handshake.headers.authorization;
  if(auth && auth.startsWith('Bearer ')) auth = auth.slice(7);
  const user = verifyJWT(auth);
  if (!user) return next(new Error("Unauthorized"));
  socket.username = user;
  return next();
});

io.on('connection', (socket) => {
  socket.on('chat message', (msg) => {
    const sender = socket.username;
    const message = (typeof msg === 'string') ? msg.slice(0,300) : '';
    const timestamp = new Date().toISOString();
    if (!message) return;
    // Save message in DB
    db.run('INSERT INTO messages (sender, message, timestamp) VALUES (?,?,?)',
      [sender, message, timestamp]
    );
    // Broadcast to all
    io.emit('chat message', { sender, message, timestamp });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Chatroom listening at http://localhost:${PORT}`);
});