// backend/src/routes/auth.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const crypto = require('crypto');

const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || JWT_SECRET; // separate secret recommended
const CAPTCHA_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes server-side TTL (we will embed timestamp in HMAC string)

// Strict rate limiter for auth endpoints to mitigate brute-force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many auth attempts from this IP, please try again later.' },
});

// Rate limiter for email-check (reduce abuse)
const checkEmailLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // max 10 checks per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many email checks, slow down.' },
});

// Zod schemas
const signupSchema = z.object({
  name: z.string().min(1).max(120),
  email: z.string().email(),
  password: z.string().min(6).max(128),
  // captcha fields expected from client
  captcha: z.object({
    a: z.number().int(),
    b: z.number().int(),
    answer: z.number().int(),
    token: z.string().min(1),
  }),
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

// Apply limiter to all auth routes (signup/login)
router.use(['/signup', '/login'], authLimiter);

/**
 * Utility: create captcha token (HMAC)
 * token payload: `${a}:${b}:${ts}` where ts = timestamp ms
 * returned token includes ts implicitly
 */
function createCaptchaToken(a, b) {
  const ts = Date.now();
  const payload = `${a}:${b}:${ts}`;
  const hmac = crypto.createHmac('sha256', CAPTCHA_SECRET).update(payload).digest('hex');
  // we return both token and ts so client doesn't need to parse it, but token contains ts so server verifies TTL
  return `${hmac}:${ts}`;
}

/**
 * Utility: verify captcha token & answer
 */
function verifyCaptchaToken(a, b, token, answer) {
  if (!token) return false;
  // token format: "<hmac>:<ts>"
  const parts = String(token).split(':');
  if (parts.length < 2) return false;
  const ts = Number(parts[parts.length - 1]);
  if (Number.isNaN(ts)) return false;
  // TTL check
  if (Date.now() - ts > CAPTCHA_TOKEN_TTL_MS) return false;
  const payload = `${a}:${b}:${ts}`;
  const expected = crypto.createHmac('sha256', CAPTCHA_SECRET).update(payload).digest('hex');
  const provided = parts.slice(0, parts.length - 1).join(':'); // in case hmac had colons (unlikely)
  // use timingSafeEqual for security
  const expectedBuf = Buffer.from(expected, 'hex');
  const providedBuf = Buffer.from(provided, 'hex');
  if (expectedBuf.length !== providedBuf.length) return false;
  try {
    if (!crypto.timingSafeEqual(expectedBuf, providedBuf)) return false;
  } catch (e) {
    return false;
  }
  // numeric answer check
  return Number(answer) === (Number(a) + Number(b));
}

/**
 * GET /api/auth/captcha
 * Returns a small math question and a signed token
 * Example response:
 * { question: "3 + 5 = ?", a: 3, b: 5, token: "<hmac:ts>" }
 */
router.get('/captcha', (req, res) => {
  // generate small numbers 1..9 to keep it user-friendly
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const token = createCaptchaToken(a, b);
  const question = `${a} + ${b} = ?`;
  return res.json({ question, a, b, token });
});

/**
 * GET /api/auth/check-email?email=
 * Returns { exists: true } if email already registered.
 * Rate-limited to prevent enumeration abuse.
 */
router.get('/check-email', checkEmailLimiter, async (req, res, next) => {
  try {
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ message: 'Invalid email' });
    const existing = await User.findOne({ email }).lean().exec();
    return res.json({ exists: Boolean(existing) });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/signup
 * Body: { name, email, password, captcha: { a,b,answer,token } }
 */
router.post('/signup', async (req, res, next) => {
  try {
    const parsed = signupSchema.parse(req.body);
    const email = parsed.email.toLowerCase();

    // CAPTCHA validation
    const { a, b, answer, token } = parsed.captcha;
    const captchaOk = verifyCaptchaToken(a, b, token, answer);
    if (!captchaOk) {
      return res.status(400).json({ message: 'Invalid captcha answer' });
    }

    const existing = await User.findOne({ email }).exec();
    if (existing) {
      return res.status(409).json({ message: 'Email already in use' });
    }

    const user = new User({ name: parsed.name, email, password: parsed.password });
    await user.save();

    const tokenJwt = signToken(user);
    const safeUser = user.toJSON ? user.toJSON() : { id: user._id, name: user.name, email: user.email };

    // cookie options (keep same as your current setup)
    const cookieMaxAge = (parseInt(process.env.JWT_COOKIE_EXPIRES_DAYS, 10) || 7) * 24 * 60 * 60 * 1000;
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: cookieMaxAge,
    };
    res.cookie('token', tokenJwt, cookieOptions);

    return res.status(201).json({ user: safeUser, token: tokenJwt });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid request', errors: err.errors });
    }
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
router.post('/login', async (req, res, next) => {
  try {
    const parsed = loginSchema.parse(req.body);
    // Find user and include password select
    const user = await User.findOne({ email: parsed.email }).select('+password').exec();
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await user.comparePassword(parsed.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const tokenJwt = signToken(user);
    const safeUser = user.toJSON ? user.toJSON() : { id: user._id, name: user.name, email: user.email };

    // set cookie
    const cookieMaxAge = (parseInt(process.env.JWT_COOKIE_EXPIRES_DAYS, 10) || 7) * 24 * 60 * 60 * 1000;
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: cookieMaxAge,
    };
    res.cookie('token', tokenJwt, cookieOptions);

    return res.json({ user: safeUser, token: tokenJwt });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ message: 'Invalid request', errors: err.errors });
    }
    next(err);
  }
});

module.exports = router;
