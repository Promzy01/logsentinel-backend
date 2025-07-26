require('dotenv').config(); // ✅ Load environment variables
const nodemailer = require('nodemailer');

// ✅ Configure transporter with Gmail and App Password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,     // e.g., xtremepark2021@gmail.com
    pass: process.env.EMAIL_PASS      // App password (not regular password)
  }
});

/**
 * Sends an alert email to the configured recipient
 * @param {string} recipientEmail - Email to send to
 * @param {string} subject - Email subject
 * @param {string} body - Email body (text)
 */
async function sendMail(recipientEmail, subject, body) {
  try {
    await transporter.sendMail({
      from: `"LogSentinel" <${process.env.EMAIL_USER}>`,
      to: recipientEmail,
      subject,
      text: body
    });

    console.log('📧 Email alert sent!');
  } catch (err) {
    console.error('❌ Email sending failed:', err.message);
  }
}

module.exports = { sendMail };
