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
import sharp from "sharp";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/beats";
const JWT_SECRET = process.env.JWT_SECRET || "defaultJwtSecret";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "data:", "blob:"],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? process.env.FRONTEND_URL : "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: false
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// stricter limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.'
});
app.use("/admin/login", authLimiter);

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
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
    } else if (path.endsWith('.webp')) {
      res.setHeader('Content-Type', 'image/webp');
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

// Helper function to validate MongoDB ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// Models
const Beat = mongoose.model("Beat", {
  title: { type: String, required: true, maxlength: 100 },
  genre: { type: String, required: true, maxlength: 50 },
  likes: { type: Number, default: 0, min: 0 },
  plays: { type: Number, default: 0, min: 0 },
  fileUrl: { type: String, required: true },
  coverUrl: String,
  date: { type: Date, default: Date.now },
  price: { type: Number, default: 100, min: 0, max: 10000 },
  featured: { type: Boolean, default: false },
  description: { type: String, maxlength: 500 }
});

const Admin = mongoose.model("Admin", {
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  password: { type: String, required: true, minlength: 6 }
});

// Create default admin if not exists
async function createDefaultAdmin() {
  try {
    const adminExists = await Admin.findOne({ username: "admin" });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 12);
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
  const convertBeat = (beat) => {
    // If beat is a Mongoose object, convert to plain object
    const plainBeat = beat.toObject ? beat.toObject() : beat;
    return {
      ...plainBeat,
      fileUrl: plainBeat.fileUrl ? `${BASE_URL}${plainBeat.fileUrl}` : null,
      coverUrl: plainBeat.coverUrl ? `${BASE_URL}${plainBeat.coverUrl}` : null
    };
  };

  if (Array.isArray(beats)) {
    return beats.map(convertBeat);
  } else if (beats) {
    return convertBeat(beats);
  }
  return beats;
}

// Input validation middleware
const validateBeatInput = (req, res, next) => {
  const { title, genre, price, description } = req.body;

  if (!title || title.trim().length === 0) {
    return res.status(400).json({ message: "Title is required" });
  }

  if (!genre || genre.trim().length === 0) {
    return res.status(400).json({ message: "Genre is required" });
  }

  if (price && (isNaN(price) || price < 0 || price > 10000)) {
    return res.status(400).json({ message: "Price must be a number between 0 and 10000" });
  }

  if (description && description.length > 500) {
    return res.status(400).json({ message: "Description too long" });
  }

  next();
};

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

    // Basic validation
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const admin = await Admin.findOne({ username });
    if (!admin) {
      // Use generic message to prevent username enumeration
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
      filter.genre = new RegExp(`^${genre}$`, 'i');
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
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

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
app.post("/beats", authenticateToken, upload.fields([{ name: "file" }, { name: "cover" }]), validateBeatInput, async (req, res) => {
  try {
    console.log("Files received:", req.files);
    console.log("Body received:", req.body);

    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }

    const fileName = req.files.file[0].filename;
    let coverName = null;

    // Process cover image if exists
    if (req.files?.cover?.[0]) {
      const coverFile = req.files.cover[0];
      const originalCoverPath = coverFile.path;

      // Create new filename with .webp extension
      const newCoverName = path.parse(coverFile.filename).name + '.webp';
      const newCoverPath = path.join(uploadsDir, newCoverName);

      try {
        // Convert image to WebP
        await sharp(originalCoverPath)
          .webp({ quality: 80 }) // 80% quality
          .toFile(newCoverPath);

        // Delete original file
        fs.unlinkSync(originalCoverPath);

        coverName = newCoverName;
        console.log("Cover converted to WebP:", coverName);
      } catch (convertError) {
        console.error("Error converting cover to WebP:", convertError);
        // In case of error, keep the original file
        coverName = coverFile.filename;
      }
    }

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
    console.log("Beat saved successfully:", beat);

    // Convert Mongoose object to plain JS object
    const beatObject = beat.toObject();
    const responseBeat = addBaseUrlToBeats(beatObject);

    res.status(201).json(responseBeat);
  } catch (e) {
    console.error("Error creating beat:", e);
    res.status(500).json({ message: "Failed to save beat", error: e.message });
  }
});

// Update beat (admin only)
app.put("/beats/:id", authenticateToken, validateBeatInput, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findByIdAndUpdate(
      req.params.id,
      {
        title: req.body.title,
        genre: req.body.genre,
        price: req.body.price,
        featured: req.body.featured,
        description: req.body.description
      },
      { new: true, runValidators: true }
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
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

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
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

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
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

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

  // Don't expose error details in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ message: 'Something went wrong' });
  }

  res.status(500).json({ message: error.message });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
});