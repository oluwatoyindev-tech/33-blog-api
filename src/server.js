"use strict";
// Blog API — posts, comments and tags with JWT auth and author-scoped permissions.
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { db, seed, slugify } = require("./db");

seed();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5003;
const SECRET = process.env.JWT_SECRET || "dev-blog-secret";
const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const token = (u) => jwt.sign({ sub: u.id, role: u.role }, SECRET, { expiresIn: "7d" });
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "Authentication required." });
  try {
    const p = jwt.verify(t, SECRET);
    const u = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(p.sub);
    if (!u) return res.status(401).json({ error: "User no longer exists." });
    req.user = u; next();
  } catch { return res.status(401).json({ error: "Invalid or expired token." }); }
}
const withAuthor = (row) => ({ ...row, author: db.prepare("SELECT name FROM users WHERE id = ?").get(row.author_id)?.name });

app.get("/health", (req, res) => res.json({ ok: true, service: "blog-api" }));

// --- Auth ---
app.post("/api/auth/register", asyncH((req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "name, email and password are required." });
  if (db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase())) return res.status(409).json({ error: "email taken." });
  const info = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?,?,?)").run(name, email.toLowerCase(), bcrypt.hashSync(password, 10));
  const u = db.prepare("SELECT * FROM users WHERE id = ?").get(Number(info.lastInsertRowid));
  res.status(201).json({ user: publicUser(u), token: token(u) });
}));
app.post("/api/auth/login", asyncH((req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || "").toLowerCase());
  if (!u || !bcrypt.compareSync(password || "", u.password_hash)) return res.status(401).json({ error: "invalid credentials." });
  res.json({ user: publicUser(u), token: token(u) });
}));

// --- Posts ---
app.get("/api/posts", asyncH((req, res) => {
  const { tag = "", search = "" } = req.query;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 10));
  const where = [], params = {};
  if (tag) { where.push("(',' || tags || ',') LIKE $tag"); params.tag = `%,${tag},%`; }
  if (search) { where.push("(title LIKE $q OR body LIKE $q)"); params.q = `%${search}%`; }
  const w = where.length ? "WHERE " + where.join(" AND ") : "";
  const total = db.prepare(`SELECT COUNT(*) AS c FROM posts ${w}`).get(params).c;
  const rows = db.prepare(`SELECT * FROM posts ${w} ORDER BY created_at DESC LIMIT $limit OFFSET $offset`)
    .all({ ...params, limit: pageSize, offset: (page - 1) * pageSize });
  res.json({ items: rows.map(withAuthor), total, page, pages: Math.ceil(total / pageSize) });
}));

app.get("/api/posts/:slug", asyncH((req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE slug = ?").get(req.params.slug);
  if (!post) return res.status(404).json({ error: "Post not found." });
  const comments = db.prepare(
    "SELECT c.id, c.body, c.created_at, u.name AS author FROM comments c JOIN users u ON u.id = c.author_id WHERE c.post_id = ? ORDER BY c.created_at"
  ).all(post.id);
  res.json({ ...withAuthor(post), tags: post.tags ? post.tags.split(",") : [], comments });
}));

app.post("/api/posts", requireAuth, asyncH((req, res) => {
  const { title, body, tags = "" } = req.body || {};
  if (!title || !body) return res.status(400).json({ error: "title and body are required." });
  let slug = slugify(title), n = 1;
  while (db.prepare("SELECT id FROM posts WHERE slug = ?").get(slug)) slug = `${slugify(title)}-${++n}`;
  const cleanTags = String(tags).split(",").map((t) => t.trim()).filter(Boolean).join(",");
  const info = db.prepare("INSERT INTO posts (author_id, title, slug, body, tags) VALUES (?,?,?,?,?)")
    .run(req.user.id, title, slug, body, cleanTags);
  res.status(201).json(withAuthor(db.prepare("SELECT * FROM posts WHERE id = ?").get(Number(info.lastInsertRowid))));
}));

function ownedOrAdmin(req, res, next) {
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Post not found." });
  if (post.author_id !== req.user.id && req.user.role !== "admin") return res.status(403).json({ error: "You can only modify your own posts." });
  req.post = post; next();
}
app.put("/api/posts/:id", requireAuth, ownedOrAdmin, asyncH((req, res) => {
  const { title = req.post.title, body = req.post.body, tags = req.post.tags } = req.body || {};
  const cleanTags = String(tags).split(",").map((t) => t.trim()).filter(Boolean).join(",");
  db.prepare("UPDATE posts SET title=?, body=?, tags=? WHERE id=?").run(title, body, cleanTags, req.post.id);
  res.json(withAuthor(db.prepare("SELECT * FROM posts WHERE id = ?").get(req.post.id)));
}));
app.delete("/api/posts/:id", requireAuth, ownedOrAdmin, asyncH((req, res) => {
  db.prepare("DELETE FROM posts WHERE id = ?").run(req.post.id);
  res.json({ ok: true });
}));

// --- Comments ---
app.post("/api/posts/:id/comments", requireAuth, asyncH((req, res) => {
  const post = db.prepare("SELECT id FROM posts WHERE id = ?").get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Post not found." });
  const { body } = req.body || {};
  if (!body || !body.trim()) return res.status(400).json({ error: "comment body is required." });
  db.prepare("INSERT INTO comments (post_id, author_id, body) VALUES (?,?,?)").run(post.id, req.user.id, body.trim());
  res.status(201).json({ ok: true });
}));

// --- Tags ---
app.get("/api/tags", asyncH((req, res) => {
  const counts = {};
  for (const { tags } of db.prepare("SELECT tags FROM posts WHERE tags != ''").all())
    tags.split(",").forEach((t) => (counts[t] = (counts[t] || 0) + 1));
  res.json(Object.entries(counts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count));
}));

app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use((err, req, res, _next) => { console.error(err); res.status(500).json({ error: "Server error." }); });

app.listen(PORT, () => console.log(`Blog API on http://localhost:${PORT}`));
