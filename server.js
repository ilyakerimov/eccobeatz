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
import mongoSanitize from 'express-mongo-sanitize';
import hpp from "hpp";
import validator from "validator";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Validate essential environment variables
if (!process.env.MONGO_URI) {
  console.error("FATAL ERROR: MONGO_URI is not defined");
  process.exit(1);
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "defaultJwtSecret") {
  console.error("FATAL ERROR: JWT_SECRET is not properly configured");
  process.exit(1);
}

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || "development";

const app = express();

// Trust proxy for rate limiting behind reverse proxy
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'", "data:"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// Body parsing middleware with limits
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: NODE_ENV === 'production' ? 100 : 1000,
  message: "Too many requests from this IP, please try again later.",
  validate: { trustProxy: true }
});
app.use(limiter);

// Additional security middleware
app.use(mongoSanitize());
app.use(hpp());

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

// Static file serving
app.use("/uploads", express.static(uploadsDir, {
  setHeaders: (res, path) => {
    if (path.endsWith('.mp3')) {
      res.setHeader('Content-Type', 'audio/mpeg');
    } else if (path.endsWith('.webp')) {
      res.setHeader('Content-Type', 'image/webp');
    }
  }
}));

// MongoDB connection - удаляем устаревшие опции
mongoose.connect(MONGO_URI)
.then(() => console.log("MongoDB connected"))
.catch((e) => {
  console.error("MongoDB connection error:", e);
  process.exit(1);
});

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
  username: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function(v) {
        return validator.isAlphanumeric(v) && v.length >= 3 && v.length <= 30;
      },
      message: 'Username must be alphanumeric and between 3-30 characters'
    }
  },
  password: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return validator.isStrongPassword(v, {
          minLength: 8,
          minLowercase: 1,
          minUppercase: 1,
          minNumbers: 1,
          minSymbols: 1
        });
      },
      message: 'Password must be at least 8 characters with uppercase, lowercase, number and symbol'
    }
  }
});

// Input validation functions
const validateBeatInput = (data) => {
  const errors = [];

  if (!validator.isLength(data.title || '', { min: 1, max: 100 })) {
    errors.push('Title must be between 1-100 characters');
  }

  if (!validator.isLength(data.genre || '', { min: 1, max: 50 })) {
    errors.push('Genre must be between 1-50 characters');
  }

  if (!validator.isInt(String(data.price || ''), { min: 0, max: 10000 })) {
    errors.push('Price must be a number between 0-10000');
  }

  if (data.description && !validator.isLength(data.description, { max: 500 })) {
    errors.push('Description must be less than 500 characters');
  }

  return errors;
};

const validateLoginInput = (data) => {
  const errors = [];

  if (!validator.isLength(data.username || '', { min: 3, max: 30 }) ||
      !validator.isAlphanumeric(data.username || '')) {
    errors.push('Invalid username format');
  }

  if (!validator.isStrongPassword(data.password || '', {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1
  })) {
    errors.push('Password does not meet security requirements');
  }

  return errors;
};

// Create default admin if not exists
async function createDefaultAdmin() {
  try {
    const adminExists = await Admin.findOne({ username: "admin" });
    if (!adminExists && process.env.DEFAULT_ADMIN_PASSWORD) {
      const hashedPassword = await bcrypt.hash(process.env.DEFAULT_ADMIN_PASSWORD, 12);
      const admin = new Admin({
        username: "admin",
        password: hashedPassword
      });
      await admin.save();
      console.log("Default admin created with provided password");
    } else if (!adminExists) {
      // Generate a random password if none provided
      const randomPassword = require('crypto').randomBytes(16).toString('hex');
      const hashedPassword = await bcrypt.hash(randomPassword, 12);
      const admin = new Admin({
        username: "admin",
        password: hashedPassword
      });
      await admin.save();
      console.log("Default admin created with random password:", randomPassword);
      console.log("PLEASE CHANGE THIS PASSWORD IMMEDIATELY!");
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
}
createDefaultAdmin();

// Multer configuration with enhanced security
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, 'file-' + uniqueSuffix + ext);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.fieldname === 'file') {
    const audioMimes = ['audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/mp3'];
    if (audioMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only audio files (MP3, WAV) are allowed'), false);
    }
  } else if (file.fieldname === 'cover') {
    const imageMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (imageMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, WebP, GIF) are allowed'), false);
    }
  } else {
    cb(new Error('Unexpected field'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 20 * 1024 * 1024,
    files: 2
  }
});

// Middleware to add base URL to beats
function addBaseUrlToBeats(beats) {
  const convertBeat = (beat) => {
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
  res.status(200).json({
    status: "OK",
    message: "Server is running",
    timestamp: new Date().toISOString()
  });
});

// Admin login endpoint
app.post("/admin/login", async (req, res) => {
  try {
    const validationErrors = validateLoginInput(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({ message: validationErrors.join(', ') });
    }

    const { username, password } = req.body;

    const fakeHash = await bcrypt.hash('dummy', 12);

    const admin = await Admin.findOne({ username });
    if (!admin) {
      await bcrypt.compare('dummy', fakeHash);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        userId: admin._id,
        username: admin.username,
        type: 'admin'
      },
      JWT_SECRET,
      {
        expiresIn: "1h",
        issuer: 'beat-server',
        audience: 'beat-client'
      }
    );

    if (NODE_ENV === 'production') {
      res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000
      });
    }

    res.json({
      token: NODE_ENV === 'production' ? undefined : token,
      username: admin.username,
      expiresIn: 3600
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ message: "Login failed" });
  }
});

// Logout endpoint
app.post("/admin/logout", (req, res) => {
  if (NODE_ENV === 'production') {
    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    });
  }
  res.json({ message: "Logged out successfully" });
});

// Get all beats with genre filter
app.get("/beats", async (req, res) => {
  try {
    const { genre, limit = 50, page = 1 } = req.query;

    const validatedLimit = Math.min(parseInt(limit) || 50, 100);
    const validatedPage = Math.max(parseInt(page) || 1, 1);

    let filter = {};

    if (genre && genre !== "all") {
      if (!validator.isLength(genre, { max: 50 })) {
        return res.status(400).json({ message: "Invalid genre parameter" });
      }
      filter.genre = genre;
    }

    const skip = (validatedPage - 1) * validatedLimit;

    const beats = await Beat.find(filter)
      .sort({ date: -1 })
      .limit(validatedLimit)
      .skip(skip);

    const total = await Beat.countDocuments(filter);

    res.json({
      beats: addBaseUrlToBeats(beats),
      pagination: {
        page: validatedPage,
        limit: validatedLimit,
        total,
        pages: Math.ceil(total / validatedLimit)
      }
    });
  } catch (e) {
    console.error("Error fetching beats:", e);
    res.status(500).json({ message: "Failed to fetch beats" });
  }
});

// Get single beat by ID
app.get("/beats/:id", async (req, res) => {
  try {
    if (!validator.isMongoId(req.params.id)) {
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
app.post("/beats", authenticateToken, upload.fields([{ name: "file" }, { name: "cover" }]), async (req, res) => {
  try {
    const validationErrors = validateBeatInput(req.body);
    if (validationErrors.length > 0) {
      if (req.files) {
        Object.values(req.files).forEach(files => {
          files.forEach(file => {
            fs.unlink(file.path, () => {});
          });
        });
      }
      return res.status(400).json({ message: validationErrors.join(', ') });
    }

    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }

    const fileName = req.files.file[0].filename;
    let coverName = null;

    if (req.files?.cover?.[0]) {
      const coverFile = req.files.cover[0];
      const originalCoverPath = coverFile.path;

      const newCoverName = 'cover-' + Date.now() + '.webp';
      const newCoverPath = path.join(uploadsDir, newCoverName);

      try {
        const image = sharp(originalCoverPath);
        const metadata = await image.metadata();

        if (metadata.width > 5000 || metadata.height > 5000) {
          throw new Error('Image dimensions too large');
        }

        await image
          .resize(800, 800, {
            fit: 'inside',
            withoutEnlargement: true
          })
          .webp({ quality: 80 })
          .toFile(newCoverPath);

        fs.unlinkSync(originalCoverPath);
        coverName = newCoverName;
      } catch (convertError) {
        console.error("Error converting cover to WebP:", convertError);
        fs.unlinkSync(originalCoverPath);
        return res.status(400).json({ message: "Invalid image file" });
      }
    }

    const beat = new Beat({
      title: validator.escape(req.body.title),
      genre: validator.escape(req.body.genre),
      price: parseInt(req.body.price) || 100,
      featured: req.body.featured === 'true',
      description: req.body.description ? validator.escape(req.body.description) : undefined,
      fileUrl: `/uploads/${fileName}`,
      coverUrl: coverName ? `/uploads/${coverName}` : undefined,
    });

    await beat.save();

    const beatObject = beat.toObject();
    const responseBeat = addBaseUrlToBeats(beatObject);

    res.status(201).json(responseBeat);
  } catch (e) {
    console.error("Error creating beat:", e);

    if (req.files) {
      Object.values(req.files).forEach(files => {
        files.forEach(file => {
          fs.unlink(file.path, () => {});
        });
      });
    }

    res.status(500).json({ message: "Failed to save beat", error: e.message });
  }
});

// Update beat (admin only)
app.put("/beats/:id", authenticateToken, async (req, res) => {
  try {
    if (!validator.isMongoId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const validationErrors = validateBeatInput(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({ message: validationErrors.join(', ') });
    }

    const beat = await Beat.findByIdAndUpdate(
      req.params.id,
      {
        title: validator.escape(req.body.title),
        genre: validator.escape(req.body.genre),
        price: parseInt(req.body.price),
        featured: req.body.featured === 'true',
        description: req.body.description ? validator.escape(req.body.description) : undefined
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
    if (!validator.isMongoId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findByIdAndDelete(req.params.id);

    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    const deleteFile = (filePath) => {
      if (filePath) {
        const fullPath = path.join(__dirname, filePath);
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
        }
      }
    };

    deleteFile(beat.fileUrl);
    deleteFile(beat.coverUrl);

    res.json({ message: "Beat deleted successfully" });
  } catch (e) {
    console.error("Error deleting beat:", e);
    res.status(500).json({ message: "Failed to delete beat" });
  }
});

// Like beat - with rate limiting
const likeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many likes from this IP, please try again later."
});
app.post("/likes/:id", likeLimiter, async (req, res) => {
  try {
    if (!validator.isMongoId(req.params.id)) {
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

// Increment play count - with rate limiting
const playLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: "Too many plays from this IP, please try again later."
});
app.post("/plays/:id", playLimiter, async (req, res) => {
  try {
    if (!validator.isMongoId(req.params.id)) {
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
    res.json(["all", ...genres.sort()]);
  } catch (e) {
    console.error("Error fetching genres:", e);
    res.status(500).json({ message: "Failed to fetch genres" });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);

  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ message: 'Too many files' });
    }
  }

  const message = NODE_ENV === 'production'
    ? 'Something went wrong'
    : error.message;

  res.status(500).json({ message });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
});