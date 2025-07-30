# LogSentinel Backend 🛡️

This is the backend API for **LogSentinel**, a log monitoring and suspicious activity detection system. It handles user authentication, file uploads, log parsing, email alerts and secure access to suspicious login records.

---

## 🔧 Tech Stack

- **Node.js** + **Express.js**
- **MongoDB Atlas** (NoSQL Database)
- **JWT** (Authentication)
- **Multer** (Log File Uploads)
- **Nodemailer** (Email Alerts)

---

## ✨ Features

| Feature                     | Public Access | Auth Required |
|----------------------------|---------------|----------------|
| Upload log file            | ✅ Yes        | ✅ Yes         |
| Receive email alerts       | ✅ Yes        | ✅ Yes         |
| View alert list (`/alerts`) | ❌ No         | ✅ Yes         |

---

## 📂 Project Structure

