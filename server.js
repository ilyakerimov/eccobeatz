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
import compression from "compression";
import crypto from "crypto";
import sanitizeHtml from "sanitize-html";
import cookieParser from "cookie-parser";
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { createReadStream } from "fs";
import { uploadToCloudStorage, deleteFromCloudStorage, getCloudStorageUrl } from "./cloud-storage.js";
import mongoosePaginate from 'mongoose-paginate-v2';

mongoose.plugin(mongoosePaginate);
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/beats";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const NODE_ENV = process.env.NODE_ENV || 'development';
const USE_CLOUD_STORAGE = process.env.USE_CLOUD_STORAGE === 'true';
const STORAGE_TYPE = USE_CLOUD_STORAGE ? 'cloud' : 'local';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'", FRONTEND_URL],
      scriptSrc: ["'self'", "'unsafe-inline'", FRONTEND_URL],
      styleSrc: ["'self'", "'unsafe-inline'", FRONTEND_URL],
      imgSrc: ["'self'", "data:", "blob:", FRONTEND_URL, BASE_URL],
      mediaSrc: ["'self'", "data:", "blob:", FRONTEND_URL, BASE_URL],
      connectSrc: ["'self'", FRONTEND_URL, BASE_URL],
      fontSrc: ["'self'", FRONTEND_URL],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"]
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Enhanced CORS configuration
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [FRONTEND_URL];
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"]
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Stricter limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.'
});
app.use("/admin/login", authLimiter);

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip} - ${req.get('User-Agent')}`);
  next();
});

// NoSQL injection protection middleware
app.use((req, res, next) => {
  const sanitize = (obj) => {
    if (obj && typeof obj === 'object') {
      for (let key in obj) {
        if (typeof obj[key] === 'string') {
          if (obj[key].startsWith('$')) {
            return res.status(400).json({ message: 'Invalid input' });
          }
        } else if (typeof obj[key] === 'object') {
          const result = sanitize(obj[key]);
          if (result) return result;
        }
      }
    }
    return null;
  };

  const bodyResult = sanitize(req.body);
  if (bodyResult) return bodyResult;

  const queryResult = sanitize(req.query);
  if (queryResult) return queryResult;

  const paramsResult = sanitize(req.params);
  if (paramsResult) return paramsResult;

  next();
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Static file serving with proper headers
if (!USE_CLOUD_STORAGE) {
  app.use("/uploads", express.static(uploadsDir, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.mp3')) {
        res.setHeader('Content-Type', 'audio/mpeg');
        res.setHeader('Content-Disposition', 'inline');
      } else if (filePath.endsWith('.webp')) {
        res.setHeader('Content-Type', 'image/webp');
      }
    }
  }));
}

// Helper function to validate MongoDB ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// Models
const Beat = mongoose.model("Beat", new mongoose.Schema({
  title: { type: String, required: true, maxlength: 100 },
  genre: { type: String, required: true, maxlength: 50 },
  likes: { type: Number, default: 0, min: 0 },
  plays: { type: Number, default: 0, min: 0 },
  fileUrl: { type: String, required: true },
  coverUrl: String,
  date: { type: Date, default: Date.now },
  price: { type: Number, default: 100, min: 0, max: 10000 },
  featured: { type: Boolean, default: false },
  description: { type: String, maxlength: 500 },
  storageType: { type: String, default: STORAGE_TYPE, enum: ['local', 'cloud'] }
}));

const Admin = mongoose.model("Admin", new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  password: { type: String, required: true, minlength: 6 },
  lastLogin: { type: Date, default: Date.now },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Number }
}));

const RefreshToken = mongoose.model("RefreshToken", new mongoose.Schema({
  token: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now, expires: '7d' }
}));

const Purchase = mongoose.model("Purchase", new mongoose.Schema({
  beatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Beat', required: true },
  email: { type: String, required: true },
  format: { type: String, enum: ['wav', 'exclusive'], required: true },
  license: { type: String, enum: ['basic', 'premium'], required: true },
  amount: { type: Number, required: true },
  paymentId: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
}));

// Create default admin if not exists
async function createDefaultAdmin() {
  try {
    console.log("Checking for default admin...");
    let admin = await Admin.findOne({ username: "admin" });

    if (!admin) {
      console.log("Admin not found, creating new one...");

      // Generate a secure random password
      const password = crypto.randomBytes(12).toString('hex');
      const hashedPassword = await bcrypt.hash(password, 12);

      admin = new Admin({
        username: "admin",
        password: hashedPassword
      });

      await admin.save();
      console.log("Default admin created. Please check the logs for the password.");
      console.log(`Username: admin`);
      console.log(`Password: ${password}`);
      console.log("Please change this password after first login!");
    } else {
      console.log("Admin account already exists.");
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
}

// MongoDB connection with improved options
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => {
  console.log("MongoDB connected");
  createDefaultAdmin();
})
.catch((e) => {
  console.error("MongoDB connection error:", e);
  process.exit(1);
});

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + crypto.randomBytes(8).toString('hex') + path.extname(file.originalname)),
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'file') {
      if (file.mimetype.startsWith('audio/')) {
        cb(null, true);
      } else {
        cb(new Error('Only audio files are allowed for the audio field'), false);
      }
    } else if (file.fieldname === 'cover') {
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
    fileSize: 50 * 1024 * 1024,
  }
});

// Generate tokens
const generateTokens = (userId, username) => {
  const accessToken = jwt.sign(
    { userId, username },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId, username },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

// Middleware to add base URL to beats
function addBaseUrlToBeats(beats) {
  const convertBeat = (beat) => {
    const plainBeat = beat.toObject ? beat.toObject() : beat;

    // Use cloud storage URL if file is stored in cloud
    if (plainBeat.storageType === 'cloud') {
      return {
        ...plainBeat,
        fileUrl: plainBeat.fileUrl ? getCloudStorageUrl(plainBeat.fileUrl) : null,
        coverUrl: plainBeat.coverUrl ? getCloudStorageUrl(plainBeat.coverUrl) : null
      };
    }

    // Use local storage URL
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

  // Sanitize HTML input
  if (description) {
    req.body.description = sanitizeHtml(description, {
      allowedTags: [],
      allowedAttributes: {}
    });
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
  res.status(200).json({
    status: "OK",
    message: "Server is running",
    storage: STORAGE_TYPE,
    environment: NODE_ENV
  });
});

// CSRF token endpoint
app.get("/csrf-token", (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');

  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,
    secure: NODE_ENV === 'production',
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost'
  });

  res.json({ csrfToken });
});

// Admin login endpoint with brute force protection
app.post("/admin/login", authLimiter, async (req, res) => {
  try {
    // Add artificial delay to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 500));

    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const admin = await Admin.findOne({ username });

    // Check if account is locked
    if (admin && admin.lockUntil && admin.lockUntil > Date.now()) {
      const retryAfter = Math.ceil((admin.lockUntil - Date.now()) / 1000);
      return res.status(429).json({
        message: "Account locked due to too many failed attempts",
        retryAfter
      });
    }

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      // Increment failed attempts
      if (admin) {
        admin.loginAttempts += 1;

        // Lock account after 5 failed attempts for 15 minutes
        if (admin.loginAttempts >= 5) {
          admin.lockUntil = Date.now() + 15 * 60 * 1000;
          admin.loginAttempts = 0;
        }

        await admin.save();
      }

      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Reset login attempts on successful login
    admin.loginAttempts = 0;
    admin.lockUntil = undefined;
    admin.lastLogin = new Date();
    await admin.save();

    const tokens = generateTokens(admin._id, admin.username);

    // Store refresh token in database
    const refreshTokenDoc = new RefreshToken({
      token: tokens.refreshToken,
      userId: admin._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    });
    await refreshTokenDoc.save();

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      token: tokens.accessToken,
      username: admin.username,
      expiresIn: 15 * 60 * 1000 // 15 minutes
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ message: "Login failed" });
  }
});

// Refresh token endpoint
app.post("/admin/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token required" });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    // Check if token exists in database
    const tokenDoc = await RefreshToken.findOne({
      token: refreshToken,
      userId: decoded.userId
    });

    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    // Generate new tokens
    const tokens = generateTokens(decoded.userId, decoded.username);

    // Update refresh token in database
    tokenDoc.token = tokens.refreshToken;
    tokenDoc.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await tokenDoc.save();

    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      token: tokens.accessToken,
      expiresIn: 15 * 60 * 1000
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

// Admin logout endpoint
app.post("/admin/logout", authenticateToken, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // Remove refresh token from database
      await RefreshToken.deleteOne({ token: refreshToken });
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax'
    });

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Logout failed" });
  }
});

// Get all beats with genre filter
app.get("/beats", async (req, res) => {
  try {
    const { genre, page = 1, limit = 10, featured } = req.query;
    let filter = {};

    if (genre && genre !== "all") {
      filter.genre = new RegExp(`^${genre}$`, 'i');
    }

    if (featured === 'true') {
      filter.featured = true;
    }

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { date: -1 }
    };

    const beats = await Beat.paginate(filter, options);

    const response = {
      ...beats,
      docs: addBaseUrlToBeats(beats.docs)
    };

    res.json(response);
  } catch (e) {
    console.error("Error fetching beats:", e);
    res.status(500).json({
      message: "Failed to fetch beats",
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
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
    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }

    const audioFile = req.files.file[0];
    let audioUrl, coverUrl;

    // Process audio file
    if (USE_CLOUD_STORAGE) {
      audioUrl = await uploadToCloudStorage(audioFile.path, `audio/${audioFile.filename}`, audioFile.mimetype);
      // Remove local file after upload
      fs.unlinkSync(audioFile.path);
    } else {
      audioUrl = `/uploads/${audioFile.filename}`;
    }

    // Process cover image if exists
    if (req.files?.cover?.[0]) {
      const coverFile = req.files.cover[0];
      const originalCoverPath = coverFile.path;

      // Convert image to WebP
      const newCoverName = path.parse(coverFile.filename).name + '.webp';
      const newCoverPath = path.join(uploadsDir, newCoverName);

      try {
        await sharp(originalCoverPath)
          .webp({ quality: 80 })
          .toFile(newCoverPath);

        // Delete original file
        fs.unlinkSync(originalCoverPath);

        if (USE_CLOUD_STORAGE) {
          coverUrl = await uploadToCloudStorage(newCoverPath, `images/${newCoverName}`, 'image/webp');
          // Remove local file after upload
          fs.unlinkSync(newCoverPath);
        } else {
          coverUrl = `/uploads/${newCoverName}`;
        }
      } catch (convertError) {
        console.error("Error converting cover to WebP:", convertError);

        if (USE_CLOUD_STORAGE) {
          coverUrl = await uploadToCloudStorage(originalCoverPath, `images/${coverFile.filename}`, coverFile.mimetype);
          fs.unlinkSync(originalCoverPath);
        } else {
          coverUrl = `/uploads/${coverFile.filename}`;
        }
      }
    }

    const beat = new Beat({
      title: req.body.title,
      genre: req.body.genre,
      price: req.body.price || 100,
      featured: req.body.featured || false,
      description: req.body.description,
      fileUrl: USE_CLOUD_STORAGE ? audioUrl : `/uploads/${audioFile.filename}`,
      coverUrl: coverUrl || undefined,
      storageType: STORAGE_TYPE
    });

    await beat.save();

    res.status(201).json(addBaseUrlToBeats(beat));
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

    const beat = await Beat.findById(req.params.id);

    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    // Delete associated files from storage
    if (beat.storageType === 'cloud') {
      // Delete from cloud storage
      if (beat.fileUrl) {
        await deleteFromCloudStorage(beat.fileUrl);
      }
      if (beat.coverUrl) {
        await deleteFromCloudStorage(beat.coverUrl);
      }
    } else {
      // Delete local files
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
    }

    // Delete from database
    await Beat.findByIdAndDelete(req.params.id);

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
    res.json(["all", ...genres.sort()]);
  } catch (e) {
    console.error("Error fetching genres:", e);
    res.status(500).json({ message: "Failed to fetch genres" });
  }
});

// Get featured beats
app.get("/beats/featured", async (req, res) => {
  try {
    const featuredBeats = await Beat.find({ featured: true }).sort({ date: -1 }).limit(5);
    res.json(addBaseUrlToBeats(featuredBeats));
  } catch (e) {
    console.error("Error fetching featured beats:", e);
    res.status(500).json({ message: "Failed to fetch featured beats" });
  }
});

// Create payment endpoint
app.post("/api/create-payment", async (req, res) => {
  try {
    const { beatId, email, format, license, amount } = req.body;

    // Validate input
    if (!isValidObjectId(beatId)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Valid email is required" });
    }

    // Check if beat exists
    const beat = await Beat.findById(beatId);
    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    // Generate a unique payment ID
    const paymentId = `pay_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;

    // Save purchase to database
    const purchase = new Purchase({
      beatId,
      email,
      format,
      license,
      amount,
      paymentId,
      status: 'pending'
    });
    await purchase.save();

    // In a real implementation, you would integrate with YooKassa here
    // For now, we'll return a mock response
    const mockPaymentData = {
      id: paymentId,
      status: 'pending',
      confirmation_url: `${BASE_URL}/api/mock-payment-success?paymentId=${paymentId}`,
      amount: {
        value: amount,
        currency: 'RUB'
      }
    };

    res.json(mockPaymentData);
  } catch (error) {
    console.error('Payment creation error:', error);
    res.status(500).json({ message: 'Payment creation failed' });
  }
});

// Mock payment success endpoint for testing
app.get("/api/mock-payment-success", async (req, res) => {
  try {
    const { paymentId } = req.query;

    // Find the purchase
    const purchase = await Purchase.findOne({ paymentId });
    if (!purchase) {
      return res.status(404).json({ message: "Purchase not found" });
    }

    // Update purchase status
    purchase.status = 'completed';
    await purchase.save();

    // Get beat info
    const beat = await Beat.findById(purchase.beatId);

    // In a real implementation, you would:
    // 1. Generate a download link for the beat
    // 2. Send an email to the customer with the download link
    // 3. For exclusive purchases, send separate tracks

    res.send(`
      <html>
        <head>
          <title>Payment Successful</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .success { color: green; font-size: 24px; }
          </style>
        </head>
        <body>
          <div class="success">✅ Payment Successful!</div>
          <p>Thank you for your purchase of "${beat.title}".</p>
          <p>An email with download instructions has been sent to ${purchase.email}.</p>
          <p><a href="${FRONTEND_URL}">Return to the website</a></p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Mock payment error:', error);
    res.status(500).send('Payment processing error');
  }
});

// Get purchase history (admin only)
app.get("/admin/purchases", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { createdAt: -1 },
      populate: 'beatId'
    };

    const purchases = await Purchase.paginate({}, options);
    res.json(purchases);
  } catch (error) {
    console.error('Error fetching purchases:', error);
    res.status(500).json({ message: 'Failed to fetch purchases' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);

  if (process.env.NODE_ENV === 'production') {
    if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ message: 'File too large' });
      }
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }

    return res.status(500).json({ message: 'Internal server error' });
  } else {
    res.status(500).json({
      message: error.message,
      stack: error.stack
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Frontend URL: ${FRONTEND_URL}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Storage Type: ${STORAGE_TYPE}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
});