// backend/src/middlewares/errorHandler.js
module.exports = function errorHandler(err, req, res, next) {
  // Log server-side detail
  console.error(err);

  // Known error shapes
  const status = err.statusCode || err.status || 500;
  const safeMessage = err.message || 'Server error';

  // In production avoid sending full stack
  const payload = { message: safeMessage };
  if (process.env.NODE_ENV !== 'production') {
    payload.stack = err.stack;
  }
  res.status(status).json(payload);
};
