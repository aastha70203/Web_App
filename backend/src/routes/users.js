// backend/src/routes/users.js
const express = require('express');
const router = express.Router();
const auth = require('../middlewares/auth');

// GET /api/users/me - return the currently authenticated user's profile
// The auth middleware should attach req.user (without password)
router.get('/me', auth, async (req, res) => {
  try {
    // req.user is fetched in the auth middleware
    res.json(req.user);
  } catch (err) {
    console.error('GET /api/users/me error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
