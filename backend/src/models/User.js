// backend/src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, select: false }, // never select password by default
}, { timestamps: true });

// Pre-save hook: hash password when created or changed
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
    try {
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;
    const hash = await bcrypt.hash(this.password, saltRounds);
    this.password = hash;
    return next();
  } catch (err) {
    return next(err);
  }

});

// Instance method to compare password
UserSchema.methods.comparePassword = async function(plain) {
  return bcrypt.compare(plain, this.password);
};

// Safe JSON output (remove password when toJSON)
UserSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
