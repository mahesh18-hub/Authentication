// auth.js content goes here
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/User.js";
import transporter from "../config/email.js";
import { verifyToken } from "../middleware/authMiddleware.js";

const router = express.Router();
const SECRET = "mysecretkey";

function isValidPassword(password) {
  return password.length >= 6 && /\d/.test(password) && /[!@#$%^&*]/.test(password);
}

// Register with Email Verification
router.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!isValidPassword(password)) {
    return res.status(400).json({ msg: "Weak password" });
  }

  User.findOne({ username })
    .then(existing => {
      if (existing) return res.status(400).json({ msg: "User exists" });
      return bcrypt.hash(password, 10);
    })
    .then(hashed => {
      const token = crypto.randomBytes(32).toString("hex");
      const newUser = new User({
        username,
        password: hashed,
        verifyToken: token,
        verifyTokenExpiry: Date.now() + 3600000
      });
      return newUser.save().then(() => {
        const link = `http://localhost:3000/verify.html?token=${token}`;
        transporter.sendMail({
          to: username,
          from: "c.sec.balls@gmail.com",
          subject: "Verify Your Email",
          html: `<p>Click <a href="${link}">here</a> to verify</p>`
        });
        res.json({ msg: "Registered. Check email for verification." });
      });
    })
    .catch(() => res.status(500).json({ msg: "Server error" }));
});

// Verify Email
router.get("/verify-email", (req, res) => {
  const { token } = req.query;

  User.findOne({
    verifyToken: token,
    verifyTokenExpiry: { $gt: Date.now() }
  })
    .then(user => {
      if (!user) return res.status(400).send("Invalid or expired token");
      user.isVerified = true;
      user.verifyToken = undefined;
      user.verifyTokenExpiry = undefined;
      return user.save().then(() =>
        res.send(`<h3>Email verified. <a href="/index.html">Login</a></h3>`)
      );
    })
    .catch(() => res.status(500).send("Verification failed"));
});

// Login
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "Invalid credentials" });
      if (!user.isVerified) return res.status(403).json({ msg: "Email not verified" });

      bcrypt.compare(password, user.password).then(match => {
        if (!match) return res.status(400).json({ msg: "Invalid credentials" });
        const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "1h" });
        res.json({ token });
      });
    })
    .catch(() => res.status(500).json({ msg: "Login error" }));
});

// Forgot Password
router.post("/forgot-password", (req, res) => {
  const { username } = req.body;
  const token = crypto.randomBytes(32).toString("hex");

  User.findOne({ username }).then(user => {
    if (!user) return res.status(400).json({ msg: "User not found" });
    user.resetToken = token;
    user.tokenExpiry = Date.now() + 3600000;
    user.save().then(() => {
      const link = `http://localhost:3000/reset-password.html?token=${token}`;
      transporter.sendMail({
        to: username,
        from: "your-email@gmail.com",
        subject: "Reset Password",
        html: `<p><a href="${link}">Reset Password</a></p>`
      });
      res.json({ msg: "Reset email sent" });
    });
  });
});

// Reset Password
router.post("/reset-password", (req, res) => {
  const { token, newPassword } = req.body;

  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ msg: "Weak password" });
  }

  User.findOne({ resetToken: token, tokenExpiry: { $gt: Date.now() } })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "Token expired" });
      bcrypt.hash(newPassword, 10).then(hashed => {
        user.password = hashed;
        user.resetToken = undefined;
        user.tokenExpiry = undefined;
        user.save().then(() => res.json({ msg: "Password reset success" }));
      });
    });
});

// Change Password
router.post("/change-password", verifyToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ msg: "New password too weak" });
  }

  User.findById(req.userId).then(user => {
    if (!user) return res.status(400).json({ msg: "User not found" });

    bcrypt.compare(oldPassword, user.password).then(match => {
      if (!match) return res.status(400).json({ msg: "Old password incorrect" });
      bcrypt.hash(newPassword, 10).then(hashed => {
        user.password = hashed;
        user.save().then(() => res.json({ msg: "Password changed" }));
      });
    });
  });
});

export default router;
