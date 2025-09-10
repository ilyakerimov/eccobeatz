import express from "express";
import mongoose from "mongoose";
import multer from "multer";
import cors from "cors";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/beats";
const JWT_SECRET = process.env.JWT_SECRET || "defaultJwtSecret";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: false
}));

app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Static file serving with proper headers
app.use("/uploads", express.static(uploadsDir, {
  setHeaders: (res, path) => {
    if (path.endsWith('.mp3')) {
      res.setHeader('Content-Type', 'audio/mpeg');
    }
  }
}));

// MongoDB connection with improved options
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch((e) => {
  console.error("MongoDB connection error:", e);
  process.exit(1);
});

// Models
const Beat = mongoose.model("Beat", {
  title: String,
  genre: String,
  likes: { type: Number, default: 0 },
  plays: { type: Number, default: 0 },
  fileUrl: String,
  coverUrl: String,
  date: { type: Date, default: Date.now },
  price: { type: Number, default: 100 },
  featured: { type: Boolean, default: false },
  description: String
});

const Admin = mongoose.model("Admin", {
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Create default admin if not exists
async function createDefaultAdmin() {
  try {
    const adminExists = await Admin.findOne({ username: "admin" });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      const admin = new Admin({
        username: "admin",
        password: hashedPassword
      });
      await admin.save();
      console.log("Default admin created: admin / admin123");
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
}
createDefaultAdmin();

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname)),
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    // Check file types
    if (file.fieldname === 'file') {
      // Audio files
      if (file.mimetype.startsWith('audio/')) {
        cb(null, true);
      } else {
        cb(new Error('Only audio files are allowed for the audio field'), false);
      }
    } else if (file.fieldname === 'cover') {
      // Image files
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed for the cover field'), false);
      }
    } else {
      cb(new Error('Unexpected field'), false);
    }
  },
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  }
});

// Middleware to add base URL to beats
function addBaseUrlToBeats(beats) {
  if (Array.isArray(beats)) {
    return beats.map(beat => ({
      ...beat._doc || beat,
      fileUrl: beat.fileUrl ? `${BASE_URL}${beat.fileUrl}` : null,
      coverUrl: beat.coverUrl ? `${BASE_URL}${beat.coverUrl}` : null
    }));
  } else if (beats) {
    return {
      ...beats._doc || beats,
      fileUrl: beats.fileUrl ? `${BASE_URL}${beats.fileUrl}` : null,
      coverUrl: beats.coverUrl ? `${BASE_URL}${beat.coverUrl}` : null
    };
  }
  return beats;
}

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", message: "Server is running" });
});

// Admin login endpoint
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: admin._id, username: admin.username }, JWT_SECRET, { expiresIn: "24h" });

    res.json({ token, username: admin.username });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ message: "Login failed" });
  }
});

// Get all beats with genre filter
app.get("/beats", async (req, res) => {
  try {
    const { genre } = req.query;
    let filter = {};

    if (genre && genre !== "all") {
      filter.genre = genre;
    }

    const beats = await Beat.find(filter).sort({ date: -1 });
    res.json(addBaseUrlToBeats(beats));
  } catch (e) {
    console.error("Error fetching beats:", e);
    res.status(500).json({ message: "Failed to fetch beats" });
  }
});

// Get single beat by ID
app.get("/beats/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    console.error("Error fetching beat:", e);
    res.status(500).json({ message: "Failed to fetch beat" });
  }
});

// Create new beat (admin only)
app.post("/beats", authenticateToken, upload.fields([{ name: "file" }, { name: "cover" }]), async (req, res) => {
  try {
    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }
    const fileName = req.files.file[0].filename;
    const coverName = req.files?.cover?.[0]?.filename;

    const beat = new Beat({
      title: req.body.title,
      genre: req.body.genre,
      price: req.body.price || 100,
      featured: req.body.featured || false,
      description: req.body.description,
      fileUrl: `/uploads/${fileName}`,
      coverUrl: coverName ? `/uploads/${coverName}` : undefined,
    });

    await beat.save();
    res.status(201).json(addBaseUrlToBeats(beat));
  } catch (e) {
    console.error("Error creating beat:", e);
    res.status(500).json({ message: "Failed to save beat" });
  }
});

// Update beat (admin only)
app.put("/beats/:id", authenticateToken, async (req, res) => {
  try {
    const beat = await Beat.findByIdAndUpdate(
      req.params.id,
      {
        title: req.body.title,
        genre: req.body.genre,
        price: req.body.price,
        featured: req.body.featured,
        description: req.body.description
      },
      { new: true }
    );

    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    console.error("Error updating beat:", e);
    res.status(500).json({ message: "Failed to update beat" });
  }
});

// Delete beat (admin only)
app.delete("/beats/:id", authenticateToken, async (req, res) => {
  try {
    const beat = await Beat.findByIdAndDelete(req.params.id);

    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    // Delete associated files
    if (beat.fileUrl) {
      const filePath = path.join(__dirname, beat.fileUrl);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    if (beat.coverUrl) {
      const coverPath = path.join(__dirname, beat.coverUrl);
      if (fs.existsSync(coverPath)) {
        fs.unlinkSync(coverPath);
      }
    }

    res.json({ message: "Beat deleted successfully" });
  } catch (e) {
    console.error("Error deleting beat:", e);
    res.status(500).json({ message: "Failed to delete beat" });
  }
});

// Like beat
app.post("/likes/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });
    beat.likes++;
    await beat.save();
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    console.error("Error liking beat:", e);
    res.status(500).json({ message: "Failed to like beat" });
  }
});

// Increment play count
app.post("/plays/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });
    beat.plays++;
    await beat.save();
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    console.error("Error incrementing plays:", e);
    res.status(500).json({ message: "Failed to increment plays" });
  }
});

// Get genres
app.get("/genres", async (req, res) => {
  try {
    const genres = await Beat.distinct("genre");
    res.json(["all", ...genres]);
  } catch (e) {
    console.error("Error fetching genres:", e);
    res.status(500).json({ message: "Failed to fetch genres" });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
  }
  res.status(500).json({ message: error.message });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
});