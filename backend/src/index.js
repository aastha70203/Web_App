// backend/src/index.js
require('dotenv').config();
const mongoose = require('mongoose');
const app = require('./app');

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('MONGO_URI is not set in .env — cannot start');
  process.exit(1);
}

async function start() {
  try {
    await mongoose.connect(MONGO_URI, {
      // recommended options are default in newer drivers
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
    });
    console.log('MongoDB connected');

    app.listen(PORT, () => {
      console.log('Server running on', PORT);
    });
  } catch (err) {
    console.error('Mongo connect error:', err);
    process.exit(1);
  }
}
start();
