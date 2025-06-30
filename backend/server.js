import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import connectDB from "./config/db.js";
import authRoutes from "./routes/auth.js";
import { verifyToken } from "./middleware/authMiddleware.js";
import User from "./models/User.js";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

connectDB();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

app.use("/api/auth", authRoutes);

app.get("/api/protected", verifyToken, (req, res) => {
  res.json({ msg: "Protected content", userId: req.userId });
});

app.get("/api/profile", verifyToken, (req, res) => {
  User.findById(req.userId)
    .then(user => res.json({ username: user.username, id: user._id }))
    .catch(() => res.status(500).json({ msg: "Error" }));
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

