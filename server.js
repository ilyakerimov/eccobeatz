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
import { Upload } from "@aws-sdk/lib-storage";
import mime from "mime-types";

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

// Yandex Cloud S3 configuration
const S3_ENDPOINT = process.env.S3_ENDPOINT || "https://storage.yandexcloud.net";
const S3_BUCKET = process.env.S3_BUCKET;
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY;
const S3_SECRET_KEY = process.env.S3_SECRET_KEY;
const S3_REGION = process.env.S3_REGION || "ru-central1";

// Initialize S3 client if credentials are provided
let s3Client = null;
if (S3_ACCESS_KEY && S3_SECRET_KEY && S3_BUCKET) {
  s3Client = new S3Client({
    region: S3_REGION,
    endpoint: S3_ENDPOINT,
    credentials: {
      accessKeyId: S3_ACCESS_KEY,
      secretAccessKey: S3_SECRET_KEY,
    },
    forcePathStyle: true,
  });
  console.log("S3 storage configured");
} else {
  console.log("S3 storage not configured, using local storage");
}

const app = express();

// Compression middleware
app.use(compression());

// Cookie parser middleware
app.use(cookieParser());

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'", FRONTEND_URL],
      scriptSrc: ["'self'", "'unsafe-inline'", FRONTEND_URL],
      styleSrc: ["'self'", "'unsafe-inline'", FRONTEND_URL],
      imgSrc: ["'self'", "data:", "blob:", FRONTEND_URL, BASE_URL, S3_ENDPOINT],
      mediaSrc: ["'self'", "data:", "blob:", FRONTEND_URL, BASE_URL, S3_ENDPOINT],
      connectSrc: ["'self'", FRONTEND_URL, BASE_URL, S3_ENDPOINT],
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
  origin: FRONTEND_URL,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"]
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
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
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// NoSQL injection protection middleware
app.use((req, res, next) => {
  const sanitize = (obj) => {
    if (obj && typeof obj === 'object') {
      for (let key in obj) {
        if (typeof obj[key] === 'string') {
          if (obj[key].startsWith('$')) {
            throw new Error('Potential NoSQL injection detected');
          }
        } else if (typeof obj[key] === 'object') {
          sanitize(obj[key]);
        }
      }
    }
  };

  try {
    sanitize(req.body);
    sanitize(req.query);
    sanitize(req.params);
    next();
  } catch (e) {
    res.status(400).json({ message: 'Invalid input' });
  }
});

// Ensure uploads directory exists for local storage
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Static file serving with proper headers (for local storage)
if (!s3Client) {
  app.use("/uploads", express.static(uploadsDir, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.mp3')) {
        res.setHeader('Content-Type', 'audio/mpeg');
        res.setHeader('Content-Disposition', 'inline');
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 day cache for audio
      } else if (filePath.endsWith('.webp')) {
        res.setHeader('Content-Type', 'image/webp');
        res.setHeader('Cache-Control', 'public, max-age=2592000'); // 30 days cache for images
      }
    }
  }));
}

// Helper function to validate MongoDB ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// File storage functions
const uploadFileToStorage = async (fileBuffer, fileName, mimeType) => {
  if (s3Client) {
    // Upload to Yandex Cloud S3
    const key = `beats/${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${fileName}`;

    const uploadParams = {
      Bucket: S3_BUCKET,
      Key: key,
      Body: fileBuffer,
      ContentType: mimeType,
      ACL: 'public-read'
    };

    try {
      const parallelUploads3 = new Upload({
        client: s3Client,
        params: uploadParams,
      });

      await parallelUploads3.done();
      return `${S3_ENDPOINT}/${S3_BUCKET}/${key}`;
    } catch (error) {
      console.error("S3 upload error:", error);
      throw new Error("Failed to upload file to cloud storage");
    }
  } else {
    // Local storage
    const filePath = path.join(uploadsDir, fileName);
    fs.writeFileSync(filePath, fileBuffer);
    return `/uploads/${fileName}`;
  }
};

const deleteFileFromStorage = async (fileUrl) => {
  if (!fileUrl) return;

  if (s3Client && fileUrl.includes(S3_ENDPOINT)) {
    // Delete from S3
    try {
      const key = fileUrl.replace(`${S3_ENDPOINT}/${S3_BUCKET}/`, '');
      const deleteParams = {
        Bucket: S3_BUCKET,
        Key: key,
      };

      await s3Client.send(new DeleteObjectCommand(deleteParams));
    } catch (error) {
      console.error("S3 delete error:", error);
    }
  } else if (fileUrl.startsWith('/uploads/')) {
    // Delete from local storage
    const filePath = path.join(__dirname, fileUrl);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
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
  description: { type: String, maxlength: 500 }
}));

const Admin = mongoose.model("Admin", new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  password: { type: String, required: true, minlength: 6 },
  lastLogin: { type: Date, default: Date.now }
}));

const RefreshToken = mongoose.model("RefreshToken", new mongoose.Schema({
  token: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  expiresAt: { type: Date, required: true }
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
})
.then(() => {
  console.log("MongoDB connected");
  createDefaultAdmin();
})
.catch((e) => {
  console.error("MongoDB connection error:", e);
  process.exit(1);
});

// Multer configuration for memory storage
const memoryStorage = multer.memoryStorage();
const upload = multer({
  storage: memoryStorage,
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
  // For S3 storage, URLs are already absolute
  if (s3Client) {
    return beats;
  }

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
    storage: s3Client ? "S3" : "local"
  });
});

// CSRF token endpoint
app.get("/csrf-token", (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');

  // Set cookie with proper settings for production
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,
    secure: NODE_ENV === 'production',
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost'
  });

  res.json({ csrfToken });
});

// Admin login endpoint with delay to prevent timing attacks
app.post("/admin/login", authLimiter, async (req, res) => {
  try {
    // Add artificial delay to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 500));

    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const admin = await Admin.findOne({ username });
    if (!admin) {
      await new Promise(resolve => setTimeout(resolve, 500));
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      await new Promise(resolve => setTimeout(resolve, 500));
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Update last login
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
    const { genre, featured } = req.query;
    let filter = {};

    if (genre && genre !== "all") {
      filter.genre = new RegExp(`^${genre}$`, 'i');
    }

    if (featured === "true") {
      filter.featured = true;
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
    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }

    const audioFile = req.files.file[0];
    let coverFile = req.files?.cover?.[0];

    // Upload audio file
    const audioFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(audioFile.originalname)}`;
    const audioUrl = await uploadFileToStorage(
      audioFile.buffer,
      audioFileName,
      audioFile.mimetype
    );

    let coverUrl = null;

    // Process cover image if exists
    if (coverFile) {
      try {
        // Convert image to WebP and resize
        const webpBuffer = await sharp(coverFile.buffer)
          .resize(500, 500, {
            fit: 'cover',
            withoutEnlargement: true
          })
          .webp({ quality: 80 })
          .toBuffer();

        const coverFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.webp`;
        coverUrl = await uploadFileToStorage(
          webpBuffer,
          coverFileName,
          'image/webp'
        );
      } catch (convertError) {
        console.error("Error processing cover image:", convertError);
        // Fallback to original image
        const coverFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(coverFile.originalname)}`;
        coverUrl = await uploadFileToStorage(
          coverFile.buffer,
          coverFileName,
          coverFile.mimetype
        );
      }
    }

    const beat = new Beat({
      title: req.body.title,
      genre: req.body.genre,
      price: req.body.price || 100,
      featured: req.body.featured || false,
      description: req.body.description,
      fileUrl: audioUrl,
      coverUrl: coverUrl,
    });

    await beat.save();

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

    // Delete associated files from storage
    await deleteFileFromStorage(beat.fileUrl);
    await deleteFileFromStorage(beat.coverUrl);

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
    const beats = await Beat.find({ featured: true }).sort({ date: -1 }).limit(10);
    res.json(addBaseUrlToBeats(beats));
  } catch (e) {
    console.error("Error fetching featured beats:", e);
    res.status(500).json({ message: "Failed to fetch featured beats" });
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

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
    process.exit(0);
  });
});

// Start server
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Frontend URL: ${FRONTEND_URL}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
  console.log(`Storage: ${s3Client ? 'S3 (Yandex Cloud)' : 'Local'}`);
});