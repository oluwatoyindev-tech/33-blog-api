"use strict";
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");
const path = require("path");

const db = new DatabaseSync(path.join(__dirname, "..", "blog.db"));
db.exec("PRAGMA foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL, tags TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

const slugify = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

function seed() {
  if (db.prepare("SELECT COUNT(*) AS c FROM users").get().c > 0) return;
  const uid = Number(db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?, 'admin')")
    .run("Jane Writer", "jane@demo.test", bcrypt.hashSync("write123", 10)).lastInsertRowid);
  const posts = [
    ["Getting started with REST APIs", "A REST API exposes resources over HTTP. This post covers the basics of routes, verbs and status codes.", "api,backend"],
    ["Why I love SQLite", "SQLite is a tiny, reliable database that lives in a single file. Great for small services and prototypes.", "database,sqlite"],
    ["Clean error handling in Express", "Centralise your error handling with a single middleware and an async wrapper. Your routes stay tidy.", "express,backend"],
  ];
  const insP = db.prepare("INSERT INTO posts (author_id, title, slug, body, tags) VALUES (?,?,?,?,?)");
  const insC = db.prepare("INSERT INTO comments (post_id, author_id, body) VALUES (?,?,?)");
  posts.forEach(([title, body, tags]) => {
    const pid = Number(insP.run(uid, title, slugify(title), body, tags).lastInsertRowid);
    insC.run(pid, uid, "Great post, thanks for sharing!");
  });
  console.log("Seeded author jane@demo.test / write123 and 3 posts.");
}

module.exports = { db, seed, slugify };
