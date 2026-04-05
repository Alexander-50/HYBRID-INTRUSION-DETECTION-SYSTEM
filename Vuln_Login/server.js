const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;
const dbPath = path.resolve(__dirname, 'testlab.sq3');
const db = new sqlite3.Database(dbPath);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'vulnerable-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Routes
app.get('/', (req, res) => res.redirect('/login'));

// Vulnerable Login Route
app.get('/login', (req, res) => {
  res.render('login', { 
    type: 'vulnerable', 
    error: req.session.error, 
    success: req.session.success,
    user: req.session.user,
    query: req.session.query
  });
  delete req.session.error;
  delete req.session.success;
  delete req.session.query;
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const source_ip = req.ip;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  req.session.query = sql;

  db.get(sql, (err, row) => {
    if (err) {
      req.session.error = "Database error: " + err.message;
      return res.redirect('/login');
    }
    if (row) {
      req.session.user = { username: row.username, role: row.role };
      req.session.success = `Login successful! Welcome, ${row.username}`;
      db.run('INSERT INTO login_attempts (username, password_attempt, source_ip, success) VALUES (?, ?, ?, ?)', [username, password, source_ip, 1]);
    } else {
      req.session.error = "Invalid credentials";
      db.run('INSERT INTO login_attempts (username, password_attempt, source_ip, success) VALUES (?, ?, ?, ?)', [username, password, source_ip, 0]);
    }
    res.redirect('/login');
  });
});

// Secure Login Route
app.get('/login-secure', (req, res) => {
  res.render('login', { 
    type: 'secure', 
    error: req.session.error, 
    success: req.session.success,
    user: req.session.user,
    query: null
  });
  delete req.session.error;
  delete req.session.success;
});

app.post('/login-secure', (req, res) => {
  const { username, password } = req.body;
  const source_ip = req.ip;
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) {
      req.session.error = "Database error";
      return res.redirect('/login-secure');
    }
    if (row) {
      req.session.user = { username: row.username, role: row.role };
      req.session.success = `Login successful! Welcome, ${row.username}`;
      db.run('INSERT INTO login_attempts (username, password_attempt, source_ip, success) VALUES (?, ?, ?, ?)', [username, password, source_ip, 1]);
    } else {
      req.session.error = "Invalid credentials";
      db.run('INSERT INTO login_attempts (username, password_attempt, source_ip, success) VALUES (?, ?, ?, ?)', [username, password, source_ip, 0]);
    }
    res.redirect('/login-secure');
  });
});

// Dashboard Route
app.get('/dashboard', (req, res) => {
  db.all('SELECT * FROM login_attempts ORDER BY attempt_time DESC LIMIT 50', (err, rows) => {
    if (err) return res.send("Error fetching logs");
    res.render('dashboard', { attempts: rows || [] });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(port, () => console.log(`🚀 SQL Injection Lab running at http://localhost:${port}`));
