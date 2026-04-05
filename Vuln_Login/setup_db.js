const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.resolve(__dirname, 'testlab.sq3');
const db = new sqlite3.Database(dbPath);

console.log('🚀 Initializing SQL Injection Test Lab Database...');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password_attempt TEXT,
    source_ip TEXT,
    success BOOLEAN,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  const users = [
    ['admin', 'admin123', 'admin@test.local', 'admin'],
    ['user1', 'pass123', 'user1@test.local', 'user'],
    ['user2', 'pass456', 'user2@test.local', 'user'],
    ['testuser', 'testpass', 'test@test.local', 'user']
  ];

  users.forEach(user => {
    db.run('INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', user);
  });

  console.log('✅ Database tables created and data seeded.');
});

db.close(() => {
    console.log('📁 Database connection closed.');
});
