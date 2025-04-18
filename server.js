require('dotenv').config();
const express = require('express');
const session = require('express-session');
const db = require('./db');
const http = require('http');
const { Server } = require('socket.io');
const { ethers } = require('ethers');
const { startMonitoring } = require('./fillMonitor');

const app = express();
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_with_strong_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set true for https
}));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// In-memory nonce store for login nonces
const nonces = new Map();
// Optional cleanup interval for old nonces
setInterval(() => {
  const now = Date.now();
  for (const [address, { timestamp }] of nonces.entries()) {
    if (now - timestamp > 5 * 60 * 1000) { // 5 minutes expiration
      nonces.delete(address);
    }
  }
}, 60 * 1000);

// Generate nonce endpoint
app.get('/api/nonce/:address', (req, res) => {
  const address = req.params.address.toLowerCase();

  if (!ethers.isAddress(address)) {
    return res.status(400).json({ error: 'Invalid Ethereum address' });
  }

  const nonce = `Login nonce: ${Math.floor(Math.random() * 1000000)}`;
  nonces.set(address, { nonce, timestamp: Date.now() });

  res.json({ nonce });
});

// MetaMask login endpoint - verify signature
app.post('/api/login-metamask', async (req, res) => {
  try {
    let { address, signature } = req.body;
    if (!address || !signature) {
      return res.status(400).json({ error: 'Address and signature required' });
    }
    address = address.toLowerCase();

    if (!ethers.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }

    const stored = nonces.get(address);
    if (!stored) {
      return res.status(400).json({ error: 'Nonce not found or expired. Request a new nonce.' });
    }

    const message = stored.nonce;

    // Verify signature: recover address from msg and signature
    const recoveredAddress = ethers.verifyMessage(message, signature).toLowerCase();

    if (recoveredAddress !== address) {
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    // Signature valid - create session
    req.session.ethAddress = address;

    // Remove nonce after successful login
    nonces.delete(address);

    res.json({ message: 'Logged in successfully' });
  } catch (error) {
    console.error('MetaMask login error:', error);
    res.status(500).json({ error: 'Server error during MetaMask login' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Error logging out' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

// Auth middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.ethAddress) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// Monitoring control and store per session address
const activeMonitors = new Map();

app.post('/api/setConfig', isAuthenticated, (req, res) => {
  const {
    privateKey,
    walletAddress,
    webhookUrl,
    tokens,
    minSize
  } = req.body;
  const ethAddress = req.session.ethAddress;

  // Validation
  if (!privateKey || !privateKey.startsWith('0x') || privateKey.length < 66) {
    return res.status(400).json({ error: 'Invalid private key format' });
  }
  if (!walletAddress || !walletAddress.startsWith('0x') || walletAddress.length !== 42) {
    return res.status(400).json({ error: 'Invalid wallet address format' });
  }
  if (!webhookUrl || !webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
    return res.status(400).json({ error: 'Invalid Discord webhook URL' });
  }

  if (!Array.isArray(tokens) || tokens.length === 0 || !tokens.every(t => typeof t === 'string' && t.trim().length > 0)) {
    return res.status(400).json({ error: 'Tokens must be a non-empty array of strings' });
  }

  if (typeof minSize !== 'number' || minSize <= 0) {
    return res.status(400).json({ error: 'minSize must be a positive number' });
  }

  try {
    const tokensStr = JSON.stringify(tokens.map(t => t.trim().toUpperCase()));

    const exists = db.prepare('SELECT 1 FROM configs WHERE ethAddress = ?').get(ethAddress);
    if (exists) {
      db.prepare(`UPDATE configs SET privateKey = ?, walletAddress = ?, webhookUrl = ?, tokens = ?, minSize = ?, is_active = 1 WHERE ethAddress = ?`)
        .run(privateKey, walletAddress, webhookUrl, tokensStr, minSize, ethAddress);
    } else {
      db.prepare(`INSERT INTO configs (ethAddress, privateKey, walletAddress, webhookUrl, tokens, minSize, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)`)
        .run(ethAddress, privateKey, walletAddress, webhookUrl, tokensStr, minSize);
    }

    // Restart monitoring if already started
    if (activeMonitors.has(ethAddress)) {
      const oldMonitor = activeMonitors.get(ethAddress);
      if (oldMonitor && oldMonitor.wsInstance) oldMonitor.wsInstance.close();
    }
    const monitorInstance = startMonitoring(io, { privateKey, walletAddress, webhookUrl, tokens: JSON.parse(tokensStr), minSize });
    activeMonitors.set(ethAddress, monitorInstance);

    res.json({ message: 'Configuration saved and monitoring started' });
  } catch (error) {
    console.error('Failed to save config or start monitoring:', error);
    res.status(500).json({ error: 'Failed to save config or start monitoring' });
  }
});

app.get('/api/getConfig', isAuthenticated, (req, res) => {
  const ethAddress = req.session.ethAddress;

  try {
    const row = db.prepare('SELECT privateKey, walletAddress, webhookUrl, tokens, minSize FROM configs WHERE ethAddress = ?').get(ethAddress);
    if (!row) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    let tokens = [];
    try {
      tokens = JSON.parse(row.tokens);
    } catch { }
    res.json({
      privateKey: row.privateKey,
      walletAddress: row.walletAddress,
      webhookUrl: row.webhookUrl,
      tokens,
      minSize: row.minSize
    });
  } catch (error) {
    console.error('Failed to load config:', error);
    res.status(500).json({ error: 'Failed to load config' });
  }
});

//stop tracking without loggin
app.post('/api/stopTracking', isAuthenticated, (req, res) => {
  const ethAddress = req.session.ethAddress;

  if (activeMonitors.has(ethAddress)) {
    const monitorInstance = activeMonitors.get(ethAddress);
    if (monitorInstance && monitorInstance.wsInstance) {
      monitorInstance.wsInstance.close();
    }
    activeMonitors.delete(ethAddress);
  }

  db.prepare('UPDATE configs SET is_active = 0 WHERE ethAddress = ?').run(ethAddress);

  res.json({ message: 'Monitoring stopped' });
});

// Load all active configs from DB and start monitoring on startup
function restoreActiveMonitors() {
  try {
    const rows = db.prepare('SELECT privateKey, walletAddress, webhookUrl, tokens, minSize, ethAddress FROM configs WHERE is_active = 1').all();

    for (const row of rows) {
      let tokens = [];
      try {
        tokens = JSON.parse(row.tokens);
      } catch {}
      
      const config = {
        privateKey: row.privateKey,
        walletAddress: row.walletAddress,
        webhookUrl: row.webhookUrl,
        tokens: tokens,
        minSize: row.minSize
      };

      try {
        const monitorInstance = startMonitoring(io, config);
        activeMonitors.set(row.ethAddress, monitorInstance);
        console.log(`✅ Restored monitoring for ethAddress ${row.ethAddress}`);
      } catch (err) {
        console.error(`Failed to restore monitor for ethAddress ${row.ethAddress}:`, err);
      }
    }
  } catch (err) {
    console.error('Error restoring active monitors:', err);
  }
}

// Call on startup
restoreActiveMonitors();

// Serve static files from /public
app.use(express.static('public'));

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Socket.io middleware (allow all connections)
io.use((socket, next) => {
  next();
});

io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });

  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// Start server
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

server.on('error', (error) => {
  console.error('Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Trying again in 5 seconds...`);
    setTimeout(() => {
      server.close();
      server.listen(PORT);
    }, 5000);
  }
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forcing server close after timeout');
    process.exit(1);
  }, 10000);
});