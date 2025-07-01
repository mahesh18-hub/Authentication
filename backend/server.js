// server.js
import express from "express";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

// Setup __dirname with ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());

// ✅ Serve frontend static files from ../frontend
app.use(express.static(path.join(__dirname, "../frontend")));

// ✅ API routes
app.use("/api/auth", authRoutes);

// ✅ Handle direct page refresh (important for SPA or plain routing)
app.get("*", (req, res) => {
  const filePath = path.join(__dirname, "../frontend", req.path);
  if (path.extname(req.path)) {
    // if file (like .html) exists, serve it
    res.sendFile(filePath, err => {
      if (err) res.status(404).send("Page not found");
    });
  } else {
    // otherwise fallback to index.html
    res.sendFile(path.join(__dirname, "../frontend/index.html"));
  }
});

// ✅ MongoDB Connection
mongoose.connect("mongodb+srv://maheshburla562:Authentication@cluster0.t3zuxnl.mongodb.net/", {
  // ❌ Remove deprecated options
  // useNewUrlParser: true,
  // useUnifiedTopology: true
}).then(() => {
  console.log("✅ MongoDB connected");
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(err => {
  console.error("❌ MongoDB connection error:", err);
});
