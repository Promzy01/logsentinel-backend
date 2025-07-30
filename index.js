// ✅ index.js (with improved register error handling)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { sendMail } = require('./mailer');

const app = express();
app.use(cors());
app.use(express.json());
const PORT = 5000;

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Schemas
const alertSchema = new mongoose.Schema({
  ip: String,
  failedAttempts: Number,
  withinSeconds: String,
  timestamp: { type: Date, default: Date.now }
});
const Alert = mongoose.model('Alert', alertSchema);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
const User = mongoose.model('User', userSchema);

// ✅ Middleware
const upload = multer({ dest: 'uploads/' });

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Forbidden' });
  }
}

// ✅ Auth Routes
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("📨 Register payload:", req.body);

    if (!email || !password) {
      return res.status(400).json({ message: 'Missing email or password' });
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashed });

    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('❌ Registration error:', err.message);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Login error' });
  }
});

// ✅ Public
app.get('/', (req, res) => {
  res.send('LogSentinel backend is running');
});

// ✅ Upload & Analyze
app.post('/upload-log', upload.single('logfile'), async (req, res) => {
  const uploadedFile = req.file;
  const userEmail = req.body.email || process.env.EMAIL_TO;

  if (!uploadedFile) return res.status(400).json({ message: 'No file uploaded.' });

  const fileContent = fs.readFileSync(path.join(__dirname, uploadedFile.path), 'utf-8');
  const lines = fileContent.split('\n');

  const patterns = [
    /\w{3} \d{1,2} \d{2}:\d{2}:\d{2}.*Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)/i,
    /\w{3} \d{1,2} \d{2}:\d{2}:\d{2}.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)/i,
    /\w{3} \d{1,2} \d{2}:\d{2}:\d{2}.*unauthorized.*from\s+(\d+\.\d+\.\d+\.\d+)/i,
    /\w{3} \d{1,2} \d{2}:\d{2}:\d{2}.*login timeout.*from\s+(\d+\.\d+\.\d+\.\d+)/i
  ];

  const ipMap = {};
  lines.forEach(line => {
    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match) {
        const timestamp = new Date(`2024 ${line.slice(0, 15)}`);
        const ip = match[1];
        if (!ipMap[ip]) ipMap[ip] = [];
        ipMap[ip].push(timestamp);
        break;
      }
    }
  });

  const suspiciousIPs = [];
  for (const [ip, times] of Object.entries(ipMap)) {
    const sorted = times.sort((a, b) => a - b);
    for (let i = 0; i <= sorted.length - 5; i++) {
      const span = (sorted[i + 4] - sorted[i]) / 1000;
      if (span <= 60) {
        const alert = await Alert.create({
          ip,
          failedAttempts: sorted.length,
          withinSeconds: span.toFixed(2)
        });

        const subject = `🚨 Suspicious IP: ${ip}`;
        const body = `IP: ${ip}\nAttempts: ${sorted.length}\nWindow: ${span.toFixed(2)}s`;

        await sendMail(userEmail, subject, body);
        suspiciousIPs.push(alert);
        break;
      }
    }
  }

  res.json({
    message: 'Log analyzed',
    suspiciousIPs,
    preview: lines.slice(0, 10)
  });
});

// ✅ View Alerts (protected)
app.get('/alerts', authMiddleware, async (req, res) => {
  try {
    const { ip, from, to } = req.query;
    const filter = {};
    if (ip) filter.ip = ip;
    if (from || to) {
      filter.timestamp = {};
      if (from) filter.timestamp.$gte = new Date(from);
      if (to) {
        const end = new Date(to);
        end.setHours(23, 59, 59, 999);
        filter.timestamp.$lte = end;
      }
    }

    const alerts = await Alert.find(filter).sort({ timestamp: -1 });
    res.json({ count: alerts.length, alerts });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch alerts' });
  }
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server live at http://localhost:${PORT}`);
});
