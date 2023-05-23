const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// In-memory storage for simplicity
const users = [];

// Secret key for JWT
const secretKey = 'your-secret-key';

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded.user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid Token' });
  }
};

// Route to handle user registration
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  const existingUser = users.find(user => user.username === username);

  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  return res.status(201).json({ message: 'User registered successfully' });
});

// Route to handle user login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);

  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ user: { username } }, secretKey, { expiresIn: '1h' });

  return res.status(200).json({ token });
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  return res.status(200).json({ message: 'Protected route accessed successfully' });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
