require('dotenv').config(); // ✅ Load .env
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { sendMail } = require('./mailer');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 5000;

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Schema
const alertSchema = new mongoose.Schema({
  ip: String,
  failedAttempts: Number,
  withinSeconds: String,
  timestamp: { type: Date, default: Date.now }
});
const Alert = mongoose.model('Alert', alertSchema);

// ✅ Upload
const upload = multer({ dest: 'uploads/' });

// ✅ Home route
app.get('/', (req, res) => {
  res.send('LogSentinel backend is running');
});

// ✅ Enhanced detection route
app.post('/upload-log', upload.single('logfile'), async (req, res) => {
  const uploadedFile = req.file;
  const userEmail = req.body.email || process.env.EMAIL_TO;

  if (!uploadedFile) {
    return res.status(400).json({ message: 'No file uploaded.' });
  }

  const filePath = path.join(__dirname, uploadedFile.path);
  const fileContent = fs.readFileSync(filePath, 'utf-8');
  const lines = fileContent.split('\n');

  // ✅ Enhanced suspicious patterns
  const failedPatterns = [
    /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)/i,
    /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)/i,
    /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*unauthorized.*from\s+(\d+\.\d+\.\d+\.\d+)/i,
    /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*login timeout.*from\s+(\d+\.\d+\.\d+\.\d+)/i
  ];

  const ipLogMap = {};

  lines.forEach(rawLine => {
    const line = rawLine.trim();

    for (const pattern of failedPatterns) {
      const match = line.match(pattern);
      if (match) {
        const timeStr = match[1];
        const ip = match[2];
        const timestamp = new Date(`2024 ${timeStr}`);
        if (!ipLogMap[ip]) ipLogMap[ip] = [];
        ipLogMap[ip].push(timestamp);
        break; // Stop at first match
      }
    }
  });

  const suspiciousIPs = [];

  for (const [ip, timestamps] of Object.entries(ipLogMap)) {
    const sorted = timestamps.sort((a, b) => a - b);

    for (let i = 0; i <= sorted.length - 5; i++) {
      const start = sorted[i];
      const end = sorted[i + 4];
      const diff = (end - start) / 1000;

      if (diff <= 60) {
        const alert = new Alert({
          ip,
          failedAttempts: sorted.length,
          withinSeconds: diff.toFixed(2)
        });

        await alert.save();

        const subject = `🚨 Suspicious IP Detected: ${ip}`;
        const body = `Suspicious activity detected by LogSentinel:\n\nFile: ${uploadedFile.originalname}\nIP: ${ip}\nAttempts: ${sorted.length}\nWindow: ${diff.toFixed(2)} seconds`;

        await sendMail(userEmail, subject, body);
        suspiciousIPs.push(alert);
        break;
      }
    }
  }

  res.json({
    message: 'Time-based log analysis complete',
    filename: uploadedFile.originalname,
    totalLines: lines.length,
    preview: lines.slice(0, 10),
    suspiciousIPs
  });
});

// ✅ Alerts history
app.get('/alerts', async (req, res) => {
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
    res.json({ count: alerts.length, filtersApplied: req.query, alerts });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running at http://localhost:${PORT}`);
});
