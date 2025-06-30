// User.js content goes here
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  isVerified: { type: Boolean, default: false },
  verifyToken: String,
  verifyTokenExpiry: Date,
  resetToken: String,
  tokenExpiry: Date
});

export default mongoose.model("User", userSchema);
