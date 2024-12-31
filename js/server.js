const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Setup database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'bloguser',
  password: 'password',
  database: 'blog'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

// Middleware for authentication
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token, 'jwtPrivateKey');
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
};

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Routes

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).send('User already registered.');
      }
      return res.status(500).send('Error registering user.');
    }
    res.send('User registered');
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    if (err || results.length === 0) return res.status(400).send('Invalid username or password.');

    const user = results[0];
    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid username or password.');

    const token = jwt.sign({ id: user.id }, 'jwtPrivateKey');
    res.send(token);
  });
});

// Create Article (auth required)
app.post('/articles', auth, (req, res) => {
  const { title, content, metaTitle, metaDescription, slug } = req.body;
  const author = req.user.id;
  const date = new Date().toISOString();
  db.query("INSERT INTO articles (title, content, author, metaTitle, metaDescription, slug, date) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [title, content, author, metaTitle, metaDescription, slug, date], (err) => {
    if (err) {
      return res.status(500).send('Error creating article.');
    }
    res.send('Article created');
  });
});

// Get Articles
app.get('/articles', (req, res) => {
  db.query("SELECT * FROM articles", (err, results) => {
    if (err) {
      return res.status(500).send('Error fetching articles.');
    }
    res.json(results);
  });
});

// Get Single Article by Slug
app.get('/articles/:slug', (req, res) => {
  const { slug } = req.params;
  db.query("SELECT * FROM articles WHERE slug = ?", [slug], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).send('Article not found.');
    }
    res.json(results[0]);
  });
});

// Fallback route to serve index.html for any other requests
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});