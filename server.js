require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { WebSocketServer, WebSocket } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-this-secret";
const isProduction = process.env.NODE_ENV === "production";

app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

const dataDir = path.join(__dirname, "data");
require("fs").mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "gamezone.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    game TEXT NOT NULL,
    points INTEGER NOT NULL CHECK(points >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);
const findUser = db.prepare("SELECT id, username, password_hash, points FROM users WHERE username = ?");
const publicUser = u => ({ id: u.id, username: u.username, points: u.points });
const signToken = u => jwt.sign({ sub: u.id, username: u.username }, JWT_SECRET, { expiresIn: "7d" });

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    if (!token) throw new Error("missing");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "سجّل الدخول للمتابعة." });
  }
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "GameZone", multiplayer: true }));
app.post("/api/auth/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[\p{L}\p{N}_-]{3,18}$/u.test(username))
    return res.status(400).json({ error: "اسم اللاعب يجب أن يكون 3–18 حرفاً أو رقماً أو _ أو -." });
  if (password.length < 8 || password.length > 72)
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون بين 8 و72 حرفاً." });
  if (findUser.get(username)) return res.status(409).json({ error: "اسم اللاعب مستخدم بالفعل." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    const user = { id: Number(result.lastInsertRowid), username, points: 0 };
    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (e) {
    res.status(500).json({ error: "تعذّر إنشاء الحساب." });
  }
});
app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const row = findUser.get(username);
  if (!row || !(await bcrypt.compare(password, row.password_hash)))
    return res.status(401).json({ error: "اسم اللاعب أو كلمة المرور غير صحيحة." });
  const user = publicUser(row);
  res.json({ token: signToken(user), user });
});
app.get("/api/me", auth, (req, res) => {
  const row = db.prepare("SELECT id, username, points FROM users WHERE id = ?").get(req.user.sub);
  if (!row) return res.status(404).json({ error: "الحساب غير موجود." });
  res.json({ user: publicUser(row) });
});
app.post("/api/scores", auth, (req, res) => {
  const game = String(req.body.game || "").slice(0, 40);
  const points = Number(req.body.points);
  if (!game || !Number.isInteger(points) || points < 0 || points > 10000)
    return res.status(400).json({ error: "نتيجة غير صالحة." });
  // Important: for competitive production games, validate scores from trusted server-side game logic.
  const tx = db.transaction(() => {
    db.prepare("INSERT INTO scores (user_id, game, points) VALUES (?, ?, ?)").run(req.user.sub, game, points);
    db.prepare("UPDATE users SET points = points + ? WHERE id = ?").run(points, req.user.sub);
  });
  tx();
  res.json({ ok: true });
});
app.get("/api/leaderboard", (_req, res) => {
  const rows = db.prepare("SELECT username, points FROM users ORDER BY points DESC, username ASC LIMIT 20").all();
  res.json({ players: rows });
});

const clients = new Set();
const rooms = new Map();
const waiting = new Set();
const cleanText = (v, max = 180) => String(v || "").replace(/[<>]/g, "").trim().slice(0, max);
function send(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
}
function broadcastRoom(room, payload) {
  for (const p of room.players) send(p.ws, payload);
}
function roomSnapshot(room) {
  return { code: room.code, players: room.players.map(p => ({ username: p.username, mark: p.mark })), board: room.board, turn: room.turn, status: room.status, winner: room.winner };
}
function createRoom(code) {
  return { code, players: [], board: Array(9).fill(""), turn: "X", status: "waiting", winner: null, createdAt: Date.now() };
}
function leaveRoom(ws) {
  const roomCode = ws.roomCode;
  if (!roomCode) { waiting.delete(ws); return; }
  const room = rooms.get(roomCode);
  ws.roomCode = null;
  if (!room) return;
  room.players = room.players.filter(p => p.ws !== ws);
  if (room.players.length === 0) rooms.delete(roomCode);
  else {
    room.status = "waiting";
    room.winner = null;
    room.board = Array(9).fill("");
    room.turn = "X";
    broadcastRoom(room, { type: "room", room: roomSnapshot(room), notice: "غادر اللاعب الآخر الغرفة." });
  }
}
function joinRoom(ws, room) {
  if (room.players.length >= 2) return send(ws, { type: "error", message: "الغرفة ممتلئة." });
  const player = { ws, username: ws.username, mark: room.players.length === 0 ? "X" : "O" };
  room.players.push(player);
  ws.roomCode = room.code;
  if (room.players.length === 2) room.status = "playing";
  broadcastRoom(room, { type: "room", room: roomSnapshot(room), notice: room.status === "playing" ? "بدأت المباراة!" : "بانتظار لاعب ثانٍ..." });
}
function matchmake(ws) {
  const available = [...waiting].find(p => p.readyState === WebSocket.OPEN && !p.roomCode && p !== ws);
  waiting.delete(ws);
  if (available) {
    waiting.delete(available);
    const code = crypto.randomBytes(3).toString("hex").toUpperCase();
    const room = createRoom(code);
    rooms.set(code, room);
    joinRoom(available, room);
    joinRoom(ws, room);
  } else {
    waiting.add(ws);
    send(ws, { type: "queue", message: "أنت في قائمة الانتظار. سنوصلك بأول لاعب متاح." });
  }
}
function checkWinner(board) {
  const lines = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  for (const [a,b,c] of lines) if (board[a] && board[a] === board[b] && board[b] === board[c]) return board[a];
  return board.every(Boolean) ? "draw" : null;
}
server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/ws") return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => wss.emit("connection", ws, req));
});
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const token = url.searchParams.get("token");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(payload.sub);
    if (!user) throw new Error("unknown user");
    ws.userId = user.id;
    ws.username = user.username;
  } catch {
    send(ws, { type: "error", message: "يجب تسجيل الدخول لاستخدام اللعب الجماعي." });
    ws.close(1008, "Authentication required");
    return;
  }
  clients.add(ws);
  send(ws, { type: "welcome", username: ws.username, online: clients.size });
  for (const c of clients) send(c, { type: "presence", online: clients.size });
  ws.on("message", raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return send(ws, { type: "error", message: "رسالة غير صالحة." }); }
    if (!msg || typeof msg.type !== "string") return;
    if (msg.type === "chat") {
      const text = cleanText(msg.text, 180);
      if (!text) return;
      const packet = { type: "chat", username: ws.username, text, at: Date.now() };
      for (const c of clients) send(c, packet);
    } else if (msg.type === "queue") {
      leaveRoom(ws); matchmake(ws);
    } else if (msg.type === "cancelQueue") {
      waiting.delete(ws); send(ws, { type: "queueCancelled" });
    } else if (msg.type === "createRoom") {
      leaveRoom(ws);
      let code;
      do { code = crypto.randomBytes(3).toString("hex").toUpperCase(); } while (rooms.has(code));
      const room = createRoom(code); rooms.set(code, room); joinRoom(ws, room);
    } else if (msg.type === "joinRoom") {
      const code = cleanText(msg.code, 8).toUpperCase();
      const room = rooms.get(code);
      if (!room) return send(ws, { type: "error", message: "لم نعثر على هذه الغرفة." });
      leaveRoom(ws); joinRoom(ws, room);
    } else if (msg.type === "move") {
      const room = rooms.get(ws.roomCode);
      if (!room || room.status !== "playing") return;
      const player = room.players.find(p => p.ws === ws);
      const cell = Number(msg.cell);
      if (!player || player.mark !== room.turn || !Number.isInteger(cell) || cell < 0 || cell > 8 || room.board[cell]) return;
      room.board[cell] = player.mark;
      const win = checkWinner(room.board);
      if (win) { room.status = "finished"; room.winner = win === "draw" ? "draw" : room.players.find(p => p.mark === win)?.username || win; }
      else room.turn = room.turn === "X" ? "O" : "X";
      broadcastRoom(room, { type: "room", room: roomSnapshot(room) });
    } else if (msg.type === "rematch") {
      const room = rooms.get(ws.roomCode);
      if (!room || room.players.length !== 2) return;
      room.board = Array(9).fill(""); room.turn = "X"; room.status = "playing"; room.winner = null;
      broadcastRoom(room, { type: "room", room: roomSnapshot(room), notice: "بدأت جولة جديدة." });
    } else if (msg.type === "leaveRoom") leaveRoom(ws);
  });
  ws.on("close", () => {
    clients.delete(ws); waiting.delete(ws); leaveRoom(ws);
    for (const c of clients) send(c, { type: "presence", online: clients.size });
  });
});
setInterval(() => {
  for (const [code, room] of rooms) if (Date.now() - room.createdAt > 1000 * 60 * 60) rooms.delete(code);
}, 10 * 60 * 1000).unref();

server.listen(PORT, () => {
  console.log(`GameZone running at http://localhost:${PORT}`);
  if (isProduction && JWT_SECRET === "dev-only-change-this-secret") console.error("WARNING: Set a strong JWT_SECRET in production.");
});
