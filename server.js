require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET; // Ensure this is set in your environment variables
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const PORT = process.env.PORT || 5000;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined in environment variables');
}

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

const users = new Map();
const messages = [];
const registeredUsers = new Map(); // Store user credentials (in production, use a real database)

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }

  if (registeredUsers.has(username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    registeredUsers.set(username, {
      password: hashedPassword,
      email,
      createdAt: new Date().toISOString()
    });
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = registeredUsers.get(username);

  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  try {
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ 
      message: 'Login successful', 
      username,
      token,
      email: user.email 
    });
  } catch (error) {
    res.status(500).json({ error: 'Error during login' });
  }
});

// Protected route example
app.get('/user/profile', verifyToken, (req, res) => {
  const user = registeredUsers.get(req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json({
    username: req.user.username,
    email: user.email,
    createdAt: user.createdAt
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

io.on('connection', (socket) => {
  console.log('New client connected');
  let currentUser = null;

  socket.on('login', (data) => {
    try {
      const decoded = jwt.verify(data.token, JWT_SECRET);
      if (registeredUsers.has(decoded.username)) {
        currentUser = decoded.username;
        users.set(socket.id, currentUser);
        io.emit('userList', Array.from(users.values()));
        socket.emit('previousMessages', messages.slice(-50)); // Send last 50 messages
      }
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });

  socket.on('sendMessage', (message) => {
    if (currentUser) {
      const messageData = {
        id: Date.now(),
        username: currentUser,
        text: message,
        timestamp: new Date().toISOString()
      };
      messages.push(messageData);
      if (messages.length > 100) messages.shift(); // Keep only last 100 messages
      io.emit('message', messageData);
    }
  });

  socket.on('disconnect', () => {
    users.delete(socket.id);
    io.emit('userList', Array.from(users.values()));
    console.log('Client disconnected');
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
