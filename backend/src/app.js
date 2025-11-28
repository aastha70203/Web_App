// backend/src/app.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const xss = require('xss');

const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');
const errorHandler = require('./middlewares/errorHandler');
const cookieParser = require('cookie-parser');
const app = express();

/**
 * sanitizeValue - recursively sanitize string values using xss
 * and remove dangerous keys for NoSQL injection (keys starting with '$' or containing '.')
 * This mutates objects/arrays in-place and never reassigns req.query.
 */
function sanitizeValue(v) {
  if (typeof v === 'string') {
    return xss(v);
  }
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) v[i] = sanitizeValue(v[i]);
    return v;
  }
  if (v && typeof v === 'object') {
    Object.keys(v).forEach((k) => {
      if (k.startsWith('$') || k.includes('.')) {
        try { delete v[k]; } catch (e) { v[k] = undefined; }
        return;
      }
      v[k] = sanitizeValue(v[k]);
    });
    return v;
  }
  return v;
}

/* --------------------------
   Basic security middleware
   -------------------------- */
app.use(helmet());

// XSS + basic NoSQL-sanitizer middleware (mutates req.body/req.params/req.query keys)
app.use((req, res, next) => {
  try {
    if (req.body) sanitizeValue(req.body);
    if (req.params) sanitizeValue(req.params);
    if (req.query && typeof req.query === 'object') {
      Object.keys(req.query).forEach((k) => {
        if (k.startsWith('$') || k.includes('.')) {
          try { delete req.query[k]; } catch (e) { req.query[k] = undefined; }
        } else {
          req.query[k] = sanitizeValue(req.query[k]);
        }
      });
    }
  } catch (err) {
    console.warn('Sanitizer middleware error:', err && err.stack ? err.stack : err);
  }
  return next();
});

/* --------------------------
   CORS configuration (dev-safe)
   -------------------------- */
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (origin === CLIENT_URL || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
};

// Register cors globally — this will handle preflight (OPTIONS) automatically.
// Do NOT add an explicit app.options('/*', ...) here; that caused your crash.
app.use(cors(corsOptions));

/* --------------------------
   Body parser + rate limiting
   -------------------------- */
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

/* --------------------------
   Routes
   -------------------------- */
app.use('/api/auth', authRoutes);
app.use('/api/notes', notesRoutes);

// health check
app.get('/health', (req, res) => res.json({ ok: true }));

/* --------------------------
   Error handler (last)
   -------------------------- */
app.use(errorHandler);

module.exports = app;

// ...
app.use(cookieParser());
