require('dotenv').config();

const path = require('path');
const http = require('http');
const crypto = require('crypto');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT || 3000);
const APP_NAME = process.env.APP_NAME || 'Chat Random Number';
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 5);
const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 30);
const DB_PATH = path.join(__dirname, 'data.sqlite');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true },
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const transporter = createTransporter();
const connectedUsers = new Map(); // userId -> socket.id

initDb();
migrateDb();

const sql = {
  createUser: db.prepare(`INSERT INTO users (email, name, number, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`),
  updateUserName: db.prepare(`UPDATE users SET name = ?, updated_at = ? WHERE id = ?`),
  findUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`),
  findUserByNumber: db.prepare(`SELECT * FROM users WHERE number = ? LIMIT 1`),
  findUserById: db.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`),

  createOtp: db.prepare(`INSERT INTO otps (email, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`),
  latestOtpByEmail: db.prepare(`SELECT * FROM otps WHERE email = ? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1`),
  markOtpUsed: db.prepare(`UPDATE otps SET used_at = ? WHERE id = ?`),

  createSession: db.prepare(`INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`),
  findSession: db.prepare(`
    SELECT sessions.*, users.id as user_id, users.email, users.name, users.number
    FROM sessions
    INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ? AND sessions.expires_at > ?
    LIMIT 1
  `),
  deleteSession: db.prepare(`DELETE FROM sessions WHERE token = ?`),

  listContacts: db.prepare(`
    SELECT c.*, u.name AS linked_name, u.number AS linked_number
    FROM contacts c
    LEFT JOIN users u ON u.id = c.peer_user_id
    WHERE c.owner_user_id = ?
    ORDER BY c.updated_at DESC, c.id DESC
  `),
  contactByOwnerAndNumber: db.prepare(`
    SELECT *
    FROM contacts
    WHERE owner_user_id = ? AND peer_number = ?
    LIMIT 1
  `),

  insertContact: db.prepare(`
    INSERT INTO contacts (
      owner_user_id, peer_number, peer_name, peer_user_id, last_message, updated_at, created_at
    ) VALUES (
      @owner_user_id, @peer_number, @peer_name, @peer_user_id, @last_message, @updated_at, @created_at
    )
  `),
  updateContact: db.prepare(`
    UPDATE contacts
    SET peer_name = @peer_name,
        peer_user_id = @peer_user_id,
        last_message = @last_message,
        updated_at = @updated_at
    WHERE id = @id
  `),

  updateContactsLinkByNumber: db.prepare(`
    UPDATE contacts
    SET peer_user_id = ?, peer_name = ?, updated_at = ?
    WHERE peer_number = ?
  `),

  insertMessage: db.prepare(`
    INSERT INTO messages (
      sender_user_id, sender_number, sender_name,
      receiver_user_id, receiver_number, receiver_name,
      body, created_at, delivered_at
    ) VALUES (
      @sender_user_id, @sender_number, @sender_name,
      @receiver_user_id, @receiver_number, @receiver_name,
      @body, @created_at, @delivered_at
    )
  `),
  messagesConversation: db.prepare(`
    SELECT *
    FROM messages
    WHERE (sender_user_id = ? AND receiver_number = ?)
       OR (sender_number = ? AND receiver_user_id = ?)
    ORDER BY created_at ASC, id ASC
  `),
  pendingIncomingForNumber: db.prepare(`
    SELECT *
    FROM messages
    WHERE receiver_number = ? AND receiver_user_id IS NULL
    ORDER BY created_at ASC, id ASC
  `),
  markMessagesDeliveredToUser: db.prepare(`
    UPDATE messages
    SET receiver_user_id = ?, delivered_at = ?
    WHERE receiver_number = ? AND receiver_user_id IS NULL
  `),
};

app.use(express.static(path.join(__dirname, 'src')));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'src', 'index.html')));
app.get('/health', (_req, res) => res.json({ ok: true, app: APP_NAME, time: new Date().toISOString() }));

app.post('/api/auth/request-otp', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Email tidak valid.' });

    const code = generateOtp();
    const expiresAt = Date.now() + OTP_TTL_MINUTES * 60 * 1000;
    const codeHash = hashOtp(email, code);

    sql.createOtp.run(email, codeHash, expiresAt, Date.now());
    await sendOtpEmail(email, code, expiresAt);

    const response = { ok: true, message: 'OTP dikirim ke email.' };
    if (!transporter) response.demoCode = code;
    return res.json(response);
  } catch (err) {
    console.error('request-otp failed:', err);
    return res.status(500).json({ error: 'Gagal mengirim OTP.' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const otp = String(req.body?.otp || '').trim();
    const name = String(req.body?.name || '').trim();

    if (!isValidEmail(email)) return res.status(400).json({ error: 'Email tidak valid.' });
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'OTP harus 6 digit.' });
    if (!name) return res.status(400).json({ error: 'Nama wajib diisi.' });

    const latestOtp = sql.latestOtpByEmail.get(email);
    if (!latestOtp) return res.status(400).json({ error: 'OTP belum diminta.' });
    if (latestOtp.used_at) return res.status(400).json({ error: 'OTP sudah dipakai.' });
    if (Date.now() > latestOtp.expires_at) return res.status(400).json({ error: 'OTP sudah expired.' });

    const expectedHash = hashOtp(email, otp);
    if (!timingSafeEqual(latestOtp.code_hash, expectedHash)) {
      return res.status(400).json({ error: 'OTP salah.' });
    }

    let user = sql.findUserByEmail.get(email);
    if (!user) {
      const number = generateUniqueNumber();
      const now = Date.now();
      const insertInfo = sql.createUser.run(email, name, number, now, now);
      user = sql.findUserById.get(insertInfo.lastInsertRowid);
    } else if (user.name !== name) {
      sql.updateUserName.run(name, Date.now(), user.id);
      user = sql.findUserById.get(user.id);
    }

    sql.markOtpUsed.run(Date.now(), latestOtp.id);
    linkContactsForUser(user);

    const token = createToken();
    const expiresAt = Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
    sql.createSession.run(token, user.id, expiresAt, Date.now());

    deliverPendingMessagesToUser(user);

    return res.json({
      ok: true,
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error('verify-otp failed:', err);
    return res.status(500).json({ error: 'Gagal verifikasi OTP.' });
  }
});

app.post('/api/auth/logout', authOptional, (req, res) => {
  const token = getTokenFromReq(req);
  if (token) sql.deleteSession.run(token);
  return res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  return res.json({ ok: true, user: publicUser(req.user) });
});

app.get('/api/contacts', authRequired, (req, res) => {
  const rows = sql.listContacts.all(req.user.id);
  const contacts = rows.map((row) => ({
    id: row.id,
    number: row.peer_number,
    name: row.linked_name || row.peer_name,
    lastMessage: row.last_message || '',
    updatedAt: row.updated_at,
    linkedUserId: row.peer_user_id || null,
  }));
  return res.json({ ok: true, contacts });
});

app.post('/api/contacts/add', authRequired, (req, res) => {
  try {
    const number = normalizeNumber(req.body?.number);

    if (!isValidNumber(number)) return res.status(400).json({ error: 'Nomor tidak valid.' });
    if (number === req.user.number) return res.status(400).json({ error: 'Itu nomor kamu sendiri.' });

    const existingPeer = sql.findUserByNumber.get(number);
    const contact = upsertContact(
      req.user,
      number,
      existingPeer?.name || `User ${number.slice(-4)}`,
      existingPeer?.id || null,
      ''
    );

    return res.json({ ok: true, contact });
  } catch (err) {
    console.error('contacts/add failed:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/api/chats/:number', authRequired, (req, res) => {
  const peerNumber = normalizeNumber(req.params.number);
  if (!isValidNumber(peerNumber)) return res.status(400).json({ error: 'Nomor tidak valid.' });

  const rows = sql.messagesConversation.all(req.user.id, peerNumber, peerNumber, req.user.id);
  return res.json({
    ok: true,
    peerNumber,
    messages: rows.map((r) => serializeMessage(r, req.user.number)),
  });
});

app.post('/api/chats/send', authRequired, (req, res) => {
  try {
    const toNumber = normalizeNumber(req.body?.toNumber);
    const body = String(req.body?.message || '').trim();

    if (!isValidNumber(toNumber)) return res.status(400).json({ error: 'Nomor tujuan tidak valid.' });
    if (!body) return res.status(400).json({ error: 'Pesan tidak boleh kosong.' });

    const recipient = sql.findUserByNumber.get(toNumber);
    const now = Date.now();

    const message = {
      sender_user_id: req.user.id,
      sender_number: req.user.number,
      sender_name: req.user.name,
      receiver_user_id: recipient?.id || null,
      receiver_number: toNumber,
      receiver_name: recipient?.name || `User ${toNumber.slice(-4)}`,
      body,
      created_at: now,
      delivered_at: recipient ? now : null,
    };

    const info = sql.insertMessage.run(message);
    const stored = sql.messagesConversation.all(req.user.id, toNumber, toNumber, req.user.id).slice(-1)[0];

    upsertContact(req.user, toNumber, message.receiver_name, recipient?.id || null, body);
    if (recipient) {
      upsertContact(recipient, req.user.number, req.user.name, req.user.id, body);
    }

    const payload = serializeMessage(stored || { ...message, id: info.lastInsertRowid }, req.user.number);
    emitMessageToUsers(payload, req.user.number, toNumber);

    return res.json({ ok: true, message: payload });
  } catch (err) {
    console.error('chats/send failed:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/api/dev/status', (_req, res) => {
  return res.json({
    ok: true,
    transporterReady: Boolean(transporter),
    connectedUsers: [...connectedUsers.keys()],
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error.' });
});

io.use((socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, '');

    const session = token ? sql.findSession.get(token, Date.now()) : null;
    if (!session) return next(new Error('Unauthorized'));

    socket.user = {
      id: session.user_id,
      email: session.email,
      name: session.name,
      number: session.number,
    };
    socket.token = token;
    return next();
  } catch (err) {
    return next(err);
  }
});

io.on('connection', (socket) => {
  const room = userRoom(socket.user.number);
  connectedUsers.set(socket.user.id, socket.id);

  socket.join(room);
  socket.emit('connected', { ok: true, user: publicUser(socket.user) });

  socket.on('disconnect', () => {
    if (connectedUsers.get(socket.user.id) === socket.id) connectedUsers.delete(socket.user.id);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`${APP_NAME} running on http://0.0.0.0:${PORT}`);
});

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      number TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      used_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_user_id INTEGER NOT NULL,
      peer_number TEXT NOT NULL,
      peer_name TEXT NOT NULL,
      peer_user_id INTEGER,
      last_message TEXT DEFAULT '',
      updated_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(owner_user_id, peer_number),
      FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(peer_user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_user_id INTEGER NOT NULL,
      sender_number TEXT NOT NULL,
      sender_name TEXT NOT NULL,
      receiver_user_id INTEGER,
      receiver_number TEXT NOT NULL,
      receiver_name TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      delivered_at INTEGER,
      FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(receiver_user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_contacts_owner_user_id ON contacts(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_contacts_peer_number ON contacts(peer_number);
    CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_user_id, receiver_number, receiver_user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_receiver_number ON messages(receiver_number, receiver_user_id);
  `);
}

function migrateDb() {
  // Older data.sqlite files can miss newer columns. This keeps /api/contacts/add from crashing.
  ensureColumns('contacts', [
    ['peer_user_id', 'INTEGER'],
    ['last_message', "TEXT DEFAULT ''"],
    ['updated_at', 'INTEGER NOT NULL DEFAULT 0'],
    ['created_at', 'INTEGER NOT NULL DEFAULT 0'],
  ]);

  ensureColumns('messages', [
    ['sender_name', "TEXT NOT NULL DEFAULT ''"],
    ['receiver_user_id', 'INTEGER'],
    ['receiver_name', "TEXT NOT NULL DEFAULT ''"],
    ['body', "TEXT NOT NULL DEFAULT ''"],
    ['created_at', 'INTEGER NOT NULL DEFAULT 0'],
    ['delivered_at', 'INTEGER'],
  ]);

  // Keep the app usable even if an older DB was created before the UNIQUE constraint existed.
  try {
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_owner_peer_unique ON contacts(owner_user_id, peer_number);`);
  } catch (err) {
    console.warn('Unique index on contacts could not be created (maybe duplicate rows already exist).', err.message);
  }
}

function ensureColumns(tableName, columns) {
  const info = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const existing = new Set(info.map((c) => c.name));

  for (const [column, definition] of columns) {
    if (!existing.has(column)) {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${column} ${definition}`);
    }
  }
}

function createTransporter() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) return null;

  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  });
}

async function sendOtpEmail(email, code, expiresAt) {
  if (!transporter) {
    console.log(`[OTP DEMO] ${email} -> ${code} (expires ${new Date(expiresAt).toISOString()})`);
    return;
  }

  await transporter.sendMail({
    from: `"${APP_NAME}" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: `${APP_NAME} OTP`,
    text: `Kode OTP kamu: ${code}. Berlaku sampai ${new Date(expiresAt).toLocaleString('id-ID')}`,
    html: `<p>Kode OTP kamu: <b style="font-size:20px">${code}</b></p><p>Berlaku sampai: ${new Date(expiresAt).toLocaleString('id-ID')}</p>`,
  });
}

function authOptional(req, _res, next) {
  const token = getTokenFromReq(req);
  if (!token) return next();

  const session = sql.findSession.get(token, Date.now());
  if (session) req.user = publicUser(session);
  return next();
}

function authRequired(req, res, next) {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const session = sql.findSession.get(token, Date.now());
  if (!session) return res.status(401).json({ error: 'Sesi tidak valid.' });

  req.user = publicUser(session);
  req.token = token;
  next();
}

function getTokenFromReq(req) {
  const header = req.headers.authorization || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  return req.headers['x-session-token'] || req.query.token || '';
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    number: user.number,
  };
}

function upsertContact(ownerUser, peerNumber, peerName, peerUserId, lastMessage) {
  const now = Date.now();
  const existing = sql.contactByOwnerAndNumber.get(ownerUser.id, peerNumber);

  if (existing) {
    sql.updateContact.run({
      id: existing.id,
      peer_name: peerName,
      peer_user_id: peerUserId ?? existing.peer_user_id ?? null,
      last_message: lastMessage ?? existing.last_message ?? '',
      updated_at: now,
    });
    return sql.contactByOwnerAndNumber.get(ownerUser.id, peerNumber);
  }

  sql.insertContact.run({
    owner_user_id: ownerUser.id,
    peer_number: peerNumber,
    peer_name: peerName,
    peer_user_id: peerUserId ?? null,
    last_message: lastMessage || '',
    updated_at: now,
    created_at: now,
  });
  return sql.contactByOwnerAndNumber.get(ownerUser.id, peerNumber);
}

function linkContactsForUser(user) {
  const now = Date.now();
  sql.updateContactsLinkByNumber.run(user.id, user.name, now, user.number);
}

function deliverPendingMessagesToUser(user) {
  const now = Date.now();
  sql.markMessagesDeliveredToUser.run(user.id, now, user.number);

  const pending = sql.pendingIncomingForNumber.all(user.number);
  for (const row of pending) {
    upsertContact(user, row.sender_number, row.sender_name, row.sender_user_id || null, row.body);
    const senderUser = row.sender_user_id ? sql.findUserById.get(row.sender_user_id) : null;
    if (senderUser) upsertContact(senderUser, user.number, user.name, user.id, row.body);
  }
}

function emitMessageToUsers(message, senderNumber, receiverNumber) {
  io.to(userRoom(senderNumber)).emit('message:new', { message });
  io.to(userRoom(receiverNumber)).emit('message:new', { message });
}

function serializeMessage(row, meNumber) {
  return {
    id: row.id,
    senderNumber: row.sender_number,
    senderName: row.sender_name,
    receiverNumber: row.receiver_number,
    receiverName: row.receiver_name,
    body: row.body,
    createdAt: row.created_at,
    deliveredAt: row.delivered_at || null,
    fromMe: row.sender_number === meNumber,
  };
}

function userRoom(number) {
  return `user:${number}`;
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeNumber(value) {
  return String(value || '').trim().replace(/\s+/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidNumber(number) {
  return /^\d{5,12}$/.test(number);
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateUniqueNumber() {
  for (let i = 0; i < 100; i++) {
    const number = String(Math.floor(1000000 + Math.random() * 9000000));
    if (!sql.findUserByNumber.get(number)) return number;
  }
  throw new Error('Gagal generate nomor unik');
}

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashOtp(email, otp) {
  return crypto.createHash('sha256').update(`${email}:${otp}`).digest('hex');
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
