// backend/src/routes/auth.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many auth requests, please try again later.' },
});

// Validation Schemas (CAPTCHA removed)
const signupSchema = z.object({
  name: z.string().min(1).max(120),
  email: z.string().email(),
  password: z.string().min(6).max(128),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6).max(128),
});

function signToken(user) {
  const payload = {
    sub: String(user._id),
    user: { id: String(user._id), name: user.name, email: user.email },
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

router.use(['/signup', '/login'], authLimiter);

// POST /api/auth/signup
router.post('/signup', async (req, res, next) => {
  try {
    const parsed = signupSchema.parse(req.body);
    const email = parsed.email.toLowerCase();

    // Check User Existence
    const existing = await User.findOne({ email }).exec();
    if (existing) {
      return res.status(409).json({ message: 'Email already in use' });
    }

    // Create User
    const user = new User({ name: parsed.name, email: parsed.email, password: parsed.password });
    await user.save();

    // Return Token
    const tokenJwt = signToken(user);
    const safeUser = user.toJSON();

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    };
    res.cookie('token', tokenJwt, cookieOptions);

    return res.status(201).json({ user: safeUser, token: tokenJwt });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid data', errors: err.errors });
    }
    next(err);
  }
});

// POST /api/auth/login
router.post('/login', async (req, res, next) => {
  try {
    const parsed = loginSchema.parse(req.body);
    const user = await User.findOne({ email: parsed.email }).select('+password').exec();
    
    if (!user || !(await user.comparePassword(parsed.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const tokenJwt = signToken(user);
    const safeUser = user.toJSON();

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    };
    res.cookie('token', tokenJwt, cookieOptions);

    return res.json({ user: safeUser, token: tokenJwt });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid request' });
    }
    next(err);
  }
});

module.exports = router;