// Echo backend — Express + Turso (libSQL, a free cloud SQLite service)
//
// Handles accounts and per-user app data (conversations, settings, profile,
// notifications — everything the frontend used to keep only in
// localStorage). Data lives in Turso's cloud database, so it survives
// container restarts, redeploys, and free-tier spin-downs.
// You need a free Turso database — see README.md for setup.

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@libsql/client");

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || "development";
const TURSO_DATABASE_URL = process.env.TURSO_DATABASE_URL;
const TURSO_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN;
const ACCOUNT_RECOVERY_DAYS = 30;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

if (!JWT_SECRET) {
  if (NODE_ENV === "production") {
    console.error("FATAL: JWT_SECRET is not set.");
    process.exit(1);
  } else {
    console.warn("WARNING: JWT_SECRET is not set — using an insecure development secret.");
  }
}
const EFFECTIVE_JWT_SECRET = JWT_SECRET || "dev-only-insecure-secret-change-me";

if (!TURSO_DATABASE_URL || !TURSO_AUTH_TOKEN) {
  console.error(
    "FATAL: TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must both be set. " +
      "Create a free database at turso.tech and set these env vars — see README.md."
  );
  process.exit(1);
}

// ---------- Database ----------
const db = createClient({ url: TURSO_DATABASE_URL, authToken: TURSO_AUTH_TOKEN });

async function query(sql, params = []) {
  try {
    const result = await db.execute({ sql, args: params });
    return result.rows;
  } catch (e) {
    console.error("Query error:", sql, e.message);
    return [];
  }
}

async function run(sql, params = []) {
  try {
    await db.execute({ sql, args: params });
    return true;
  } catch (e) {
    console.error("Run error:", sql, e.message);
    return false;
  }
}

async function initDatabase() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      deleted INTEGER NOT NULL DEFAULT 0,
      deleted_at TEXT,
      data TEXT NOT NULL DEFAULT '{}'
    )
  `);
  console.log("Connected to Turso database and verified tables.");
  await purgeExpiredDeletedAccounts();
}

async function getUserByEmail(email) {
  const results = await query("SELECT * FROM users WHERE email = ?", [String(email).toLowerCase()]);
  return results[0] || null;
}

async function getUserByUsername(username) {
  const results = await query("SELECT * FROM users WHERE username = ?", [String(username).toLowerCase()]);
  return results[0] || null;
}

// Login accepts either an email or a username in one field, same as the
// frontend's "Email or username" field.
async function getUserByIdentifier(identifier) {
  const value = String(identifier || "").trim().toLowerCase();
  if (!value) return null;
  if (value.includes("@")) return getUserByEmail(value);
  return getUserByUsername(value);
}

function toPublicUser(row) {
  if (!row) return null;
  return {
    id: row.email,
    email: row.email,
    username: row.username,
    name: row.name,
    createdAt: row.created_at,
  };
}

// The default app-state shape a brand new account starts with — mirrors
// STORE.settings / STORE.palette / STORE.notifItems / conversations in
// index.html so a fresh account renders exactly like the demo did, just
// with an empty conversation list instead of sample data.
function freshAppData(name, username) {
  return {
    conversations: [],
    notifItems: [],
    sharedMedia: [],
    sharedFiles: [],
    chatThemes: {},
    settings: {
      theme: "dark",
      density: "comfortable",
      fontSize: "md",
      messageStyle: "bubbles",
      chatBackground: "default",
      customAccent: { primary: null, secondary: null },
      notifications: { messages: true, previews: true, sound: false, mentionsOnly: false },
      privacy: { readReceipts: true, typingIndicators: true, lastSeen: true, profileVisibility: "everyone" },
      chat: { enterToSend: true, linkPreviews: true, autoDownload: "wifi" },
      accessibility: { reduceMotion: false, highContrast: false, keyboardHints: true },
    },
    palette: "signal",
    profile: {
      name,
      handle: "@" + username,
      bio: "",
      statusMessage: "",
      avatarColor: "#7C5CFC",
      status: "online",
    },
  };
}

async function purgeExpiredDeletedAccounts() {
  const rows = await query("SELECT email, deleted_at FROM users WHERE deleted = 1");
  const now = Date.now();
  for (const r of rows) {
    if (!r.deleted_at) continue;
    const days = (now - new Date(r.deleted_at).getTime()) / 86400000;
    if (days > ACCOUNT_RECOVERY_DAYS) await run("DELETE FROM users WHERE email = ?", [r.email]);
  }
}
setInterval(purgeExpiredDeletedAccounts, 6 * 60 * 60 * 1000);

// ---------- App ----------
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "8mb" }));

const allowedOrigins = CORS_ORIGIN === "*" ? "*" : CORS_ORIGIN.split(",").map((s) => s.trim());
app.use(cors({ origin: allowedOrigins, credentials: false }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later." },
});

function signToken(email) {
  return jwt.sign({ email }, EFFECTIVE_JWT_SECRET, { expiresIn: "30d" });
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  // sendBeacon (used for the best-effort save-on-tab-close) can't set
  // custom headers, so it falls back to a ?token= query param instead.
  const token = header.startsWith("Bearer ") ? header.slice(7) : (req.query.token || null);
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  try {
    const payload = jwt.verify(token, EFFECTIVE_JWT_SECRET);
    const user = await getUserByEmail(payload.email);
    if (!user || user.deleted) return res.status(401).json({ error: "Account not found" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired session" });
  }
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function isValidUsername(username) {
  return typeof username === "string" && /^[a-zA-Z0-9_.]{3,20}$/.test(username);
}

// Wrap async route handlers so a thrown/rejected error returns 500 instead of hanging
const ah = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// ---------- Auth routes ----------
app.post("/api/auth/register", authLimiter, ah(async (req, res) => {
  const { name, password } = req.body || {};
  const email = String(req.body?.email || "").trim().toLowerCase();
  const username = String(req.body?.username || "").trim().toLowerCase();

  if (!email || !isValidEmail(email) || !name || !username || !password) {
    return res.status(400).json({ error: "Name, username, a valid email, and a password are required" });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: "Username must be 3–20 characters: letters, numbers, underscores only" });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  const existingByEmail = await getUserByEmail(email);
  if (existingByEmail && !existingByEmail.deleted) {
    return res.status(409).json({ error: "An account with that email already exists" });
  }
  const existingByUsername = await getUserByUsername(username);
  if (existingByUsername && !existingByUsername.deleted) {
    return res.status(409).json({ error: "That username is already taken" });
  }

  const hash = bcrypt.hashSync(password, 10);
  const createdAt = new Date().toISOString();
  if (existingByEmail && existingByEmail.deleted) await run("DELETE FROM users WHERE email = ?", [email]);

  const displayName = String(name).trim();
  await run(
    "INSERT INTO users (email, username, name, password_hash, created_at, data) VALUES (?, ?, ?, ?, ?, ?)",
    [email, username, displayName, hash, createdAt, JSON.stringify(freshAppData(displayName, username))]
  );
  const user = await getUserByEmail(email);
  const token = signToken(email);
  res.status(201).json({ token, user: toPublicUser(user) });
}));

app.post("/api/auth/login", authLimiter, ah(async (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password) {
    return res.status(400).json({ error: "Email/username and password are required" });
  }
  const user = await getUserByIdentifier(identifier);
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    return res.status(401).json({ error: "That email/username or password looks incorrect" });
  }
  let restored = false;
  if (user.deleted) {
    await run("UPDATE users SET deleted = 0, deleted_at = NULL WHERE email = ?", [user.email]);
    restored = true;
  }
  const token = signToken(user.email);
  res.json({ token, user: toPublicUser(await getUserByEmail(user.email)), restored });
}));

// ---------- Current-user data routes ----------
app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: toPublicUser(req.user), data: JSON.parse(req.user.data || "{}") });
});

app.put("/api/me/data", requireAuth, ah(async (req, res) => {
  const { data } = req.body || {};
  if (!data || typeof data !== "object") return res.status(400).json({ error: "Missing data payload" });
  await run("UPDATE users SET data = ? WHERE email = ?", [JSON.stringify(data), req.user.email]);
  res.json({ ok: true });
}));

// navigator.sendBeacon() (used by the frontend's best-effort save-on-tab-close)
// always sends POST and can't set an Authorization header, so it hits this
// separate route instead of PUT /api/me/data — same handler logic, just
// reachable the way a beacon can actually call it.
app.post("/api/me/data/beacon", requireAuth, ah(async (req, res) => {
  const { data } = req.body || {};
  if (!data || typeof data !== "object") return res.status(400).json({ error: "Missing data payload" });
  await run("UPDATE users SET data = ? WHERE email = ?", [JSON.stringify(data), req.user.email]);
  res.json({ ok: true });
}));

app.delete("/api/me", requireAuth, ah(async (req, res) => {
  const { data } = req.body || {};
  if (data && typeof data === "object") {
    await run("UPDATE users SET data = ? WHERE email = ?", [JSON.stringify(data), req.user.email]);
  }
  await run("UPDATE users SET deleted = 1, deleted_at = ? WHERE email = ?", [
    new Date().toISOString(),
    req.user.email,
  ]);
  res.json({ ok: true, recoveryDays: ACCOUNT_RECOVERY_DAYS });
}));

app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- Serve frontend ----------
const PUBLIC_DIR = path.join(__dirname, "public");
const ROOT_INDEX = path.join(__dirname, "index.html");
const FRONTEND_DIR = fs.existsSync(path.join(PUBLIC_DIR, "index.html"))
  ? PUBLIC_DIR
  : fs.existsSync(ROOT_INDEX)
  ? __dirname
  : null;

if (FRONTEND_DIR) {
  console.log(`Serving frontend from: ${FRONTEND_DIR}`);
  app.use(express.static(FRONTEND_DIR, { index: false }));
  app.get(/^(?!\/api\/).*/, (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, "index.html"));
  });
} else {
  console.warn("No index.html found in ./public or the repo root — this deployment will only serve the API.");
}

app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

// ---------- Start server ----------
initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Echo backend listening on port ${PORT} (${NODE_ENV})`);
    });
  })
  .catch((e) => {
    console.error("FATAL: could not connect to Turso database:", e.message);
    process.exit(1);
  });
