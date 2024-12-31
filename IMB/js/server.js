const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Setup database
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
  db.run("CREATE TABLE articles (id INTEGER PRIMARY KEY, title TEXT, content TEXT, author TEXT, metaTitle TEXT, metaDescription TEXT, slug TEXT, date TEXT)");
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

// Routes

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
    if (err) {
      return res.status(400).send('User already registered.');
    }
    res.send('User registered');
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) return res.status(400).send('Invalid username or password.');

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
  db.run("INSERT INTO articles (title, content, author, metaTitle, metaDescription, slug, date) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [title, content, author, metaTitle, metaDescription, slug, date], function(err) {
    if (err) {
      return res.status(400).send('Error creating article.');
    }
    res.send('Article created');
  });
});

// Get Articles
app.get('/articles', (req, res) => {
  db.all("SELECT * FROM articles", [], (err, articles) => {
    if (err) {
      return res.status(400).send('Error fetching articles.');
    }
    res.json(articles);
  });
});

// Get Single Article by Slug
app.get('/articles/:slug', (req, res) => {
  const { slug } = req.params;
  db.get("SELECT * FROM articles WHERE slug = ?", [slug], (err, article) => {
    if (err || !article) {
      return res.status(404).send('Article not found.');
    }
    res.json(article);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});