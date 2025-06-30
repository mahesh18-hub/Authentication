const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false },
  verifyToken: String,
  verifyTokenExpiry: Date,
  resetToken: String,
  tokenExpiry: Date,
});
