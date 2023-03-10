const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('./models/User');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
console.log(process.env.EMAIL);

app.use(cors());
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/mern-auth', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection = mongoose.connection;
connection.once('open', () => {
  console.log('MongoDB database connection established successfully');
});

// Register User
app.post('/register', async (req, res) => {
  const { name, email } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }
  // generate random password
  const password = Math.floor(1000 + Math.random() * 9000).toString();
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create new user

  const newUser = new User({ name, email, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).json({ message: 'User created successfully', newUser });

    const user = await User.findOne({ email });
    // Create token
    const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

    // Send email with verify password link
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      service: 'gmail',
      port: 587,
      secure: false,

      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASS,
      },
    });
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: 'Set Password',
      text: `Click the link to set your password: http://localhost:3000/password/${token}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).json({ message: 'Something went wrong', error });
      } else {
        console.log('Email sent: ' + info.response);
        res.json({ message: 'Email sent' });
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Check password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Create token
  const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

  res.json({ token });
});

// verify user and send email
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  // Create token
  const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

  // Send email with reset password link
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    service: 'gmail',
    port: 587,
    secure: false,

    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASS,
    },
  });
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'Reset Password',
    text: `Click the link to set your password: http://localhost:3000/reset-password/${token}`,
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).json({ message: 'Something went wrong', error });
    } else {
      console.log('Email sent: ' + info.response);
      res.json({ message: 'Email sent' });
    }
  });
});
// set Password
app.post('/password', async (req, res) => {
  const { token, password } = req.body;

  try {
    // Verify token
    const decoded = jwt.verify(token, 'secret');
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Update password

    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    res.json({ message: 'Password setted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
});
app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
