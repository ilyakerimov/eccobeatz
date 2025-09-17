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

// Конфигурация
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

// Инициализация приложения
const app = express();

// Модели
const BeatSchema = new mongoose.Schema({
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

const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  password: { type: String, required: true, minlength: 6 },
  lastLogin: { type: Date, default: Date.now }
});

const RefreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  expiresAt: { type: Date, required: true }
});

const Beat = mongoose.model("Beat", BeatSchema);
const Admin = mongoose.model("Admin", AdminSchema);
const RefreshToken = mongoose.model("RefreshToken", RefreshTokenSchema);

// Утилиты
const createUploadsDir = () => {
  const uploadsDir = path.join(__dirname, "uploads");
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
  return uploadsDir;
};

const generateTokens = (userId, username) => ({
  accessToken: jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '15m' }),
  refreshToken: jwt.sign({ userId, username }, JWT_REFRESH_SECRET, { expiresIn: '7d' })
});

const addBaseUrlToBeats = (beats) => {
  const convertBeat = (beat) => ({
    ...beat.toObject ? beat.toObject() : beat,
    fileUrl: beat.fileUrl ? `${BASE_URL}${beat.fileUrl}` : null,
    coverUrl: beat.coverUrl ? `${BASE_URL}${beat.coverUrl}` : null
  });

  return Array.isArray(beats) ? beats.map(convertBeat) : convertBeat(beats);
};

const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

// Middleware
const noSqlInjectionProtection = (req, res, next) => {
  const sanitize = (obj) => {
    for (let key in obj) {
      if (typeof obj[key] === 'string' && obj[key].startsWith('$')) {
        throw new Error('Potential NoSQL injection detected');
      } else if (typeof obj[key] === 'object') {
        sanitize(obj[key]);
      }
    }
  };

  try {
    ['body', 'query', 'params'].forEach(source => sanitize(req[source]));
    next();
  } catch (e) {
    res.status(400).json({ message: 'Invalid input' });
  }
};

const validateBeatInput = (req, res, next) => {
  const { title, genre, price, description } = req.body;

  if (!title?.trim()) return res.status(400).json({ message: "Title is required" });
  if (!genre?.trim()) return res.status(400).json({ message: "Genre is required" });
  if (price && (isNaN(price) || price < 0 || price > 10000)) {
    return res.status(400).json({ message: "Price must be a number between 0 and 10000" });
  }
  if (description?.length > 500) return res.status(400).json({ message: "Description too long" });

  if (description) {
    req.body.description = sanitizeHtml(description, { allowedTags: [], allowedAttributes: {} });
  }

  next();
};

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

// Инициализация
const uploadsDir = createUploadsDir();
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname)}`)
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const isAudio = file.fieldname === 'file' && file.mimetype.startsWith('audio/');
    const isImage = file.fieldname === 'cover' && file.mimetype.startsWith('image/');

    if (isAudio || isImage) return cb(null, true);
    cb(new Error(`Unexpected field or file type for ${file.fieldname}`), false);
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

const createDefaultAdmin = async () => {
  try {
    let admin = await Admin.findOne({ username: "admin" });
    if (!admin) {
      const password = crypto.randomBytes(12).toString('hex');
      const hashedPassword = await bcrypt.hash(password, 12);

      admin = await Admin.create({
        username: "admin",
        password: hashedPassword
      });

      console.log(`Default admin created. Username: admin, Password: ${password}`);
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
};

// Конфигурация приложения
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
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
  origin: FRONTEND_URL,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"]
}));

app.options('*', cors());
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
}));

app.use("/admin/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
}));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
  next();
});

app.use(noSqlInjectionProtection);

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

// Роуты
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", message: "Server is running" });
});

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

app.post("/admin/login", async (req, res) => {
  try {
    await new Promise(resolve => setTimeout(resolve, 500)); // Защита от timing attacks

    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const admin = await Admin.findOne({ username });
    const validPassword = admin && await bcrypt.compare(password, admin.password);

    if (!validPassword) {
      await new Promise(resolve => setTimeout(resolve, 500));
      return res.status(401).json({ message: "Invalid credentials" });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const tokens = generateTokens(admin._id, admin.username);
    await RefreshToken.create({
      token: tokens.refreshToken,
      userId: admin._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      token: tokens.accessToken,
      username: admin.username,
      expiresIn: 15 * 60 * 1000
    });
  } catch (e) {
    res.status(500).json({ message: "Login failed" });
  }
});

app.post("/admin/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: "Refresh token required" });

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const tokenDoc = await RefreshToken.findOne({ token: refreshToken, userId: decoded.userId });

    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const tokens = generateTokens(decoded.userId, decoded.username);
    tokenDoc.token = tokens.refreshToken;
    tokenDoc.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await tokenDoc.save();

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ token: tokens.accessToken, expiresIn: 15 * 60 * 1000 });
  } catch (error) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

app.post("/admin/logout", authenticateToken, async (req, res) => {
  try {
    await RefreshToken.deleteOne({ token: req.cookies.refreshToken });
    res.clearCookie('refreshToken', {
      domain: NODE_ENV === 'production' ? new URL(FRONTEND_URL).hostname : 'localhost',
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax'
    });
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Logout failed" });
  }
});

app.get("/beats", async (req, res) => {
  try {
    const filter = req.query.genre && req.query.genre !== "all"
      ? { genre: new RegExp(`^${req.query.genre}$`, 'i') }
      : {};

    const beats = await Beat.find(filter).sort({ date: -1 });
    res.json(addBaseUrlToBeats(beats));
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch beats" });
  }
});

app.get("/beats/:id", async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findById(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });

    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch beat" });
  }
});

app.post("/beats", authenticateToken, upload.fields([{ name: "file" }, { name: "cover" }]), validateBeatInput, async (req, res) => {
  try {
    if (!req.files?.file?.[0]) {
      return res.status(400).json({ message: "Audio file is required" });
    }

    let coverName = null;
    if (req.files?.cover?.[0]) {
      const coverFile = req.files.cover[0];
      const newCoverName = `${path.parse(coverFile.filename).name}.webp`;

      await sharp(coverFile.path)
        .webp({ quality: 80 })
        .toFile(path.join(uploadsDir, newCoverName));

      fs.unlinkSync(coverFile.path);
      coverName = newCoverName;
    }

    const beat = await Beat.create({
      title: req.body.title,
      genre: req.body.genre,
      price: req.body.price || 100,
      featured: req.body.featured || false,
      description: req.body.description,
      fileUrl: `/uploads/${req.files.file[0].filename}`,
      coverUrl: coverName ? `/uploads/${coverName}` : undefined,
    });

    res.status(201).json(addBaseUrlToBeats(beat));
  } catch (e) {
    res.status(500).json({ message: "Failed to save beat", error: e.message });
  }
});

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

    if (!beat) return res.status(404).json({ message: "Beat not found" });
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    res.status(500).json({ message: "Failed to update beat" });
  }
});

app.delete("/beats/:id", authenticateToken, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findByIdAndDelete(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });

    const deleteFile = (filePath) => {
      if (filePath && fs.existsSync(path.join(__dirname, filePath))) {
        fs.unlinkSync(path.join(__dirname, filePath));
      }
    };

    deleteFile(beat.fileUrl);
    deleteFile(beat.coverUrl);

    res.json({ message: "Beat deleted successfully" });
  } catch (e) {
    res.status(500).json({ message: "Failed to delete beat" });
  }
});

app.post("/likes/:id", async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findByIdAndUpdate(
      req.params.id,
      { $inc: { likes: 1 } },
      { new: true }
    );

    if (!beat) return res.status(404).json({ message: "Beat not found" });
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    res.status(500).json({ message: "Failed to like beat" });
  }
});

app.post("/plays/:id", async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid beat ID" });
    }

    const beat = await Beat.findByIdAndUpdate(
      req.params.id,
      { $inc: { plays: 1 } },
      { new: true }
    );

    if (!beat) return res.status(404).json({ message: "Beat not found" });
    res.json(addBaseUrlToBeats(beat));
  } catch (e) {
    res.status(500).json({ message: "Failed to increment plays" });
  }
});

app.get("/genres", async (req, res) => {
  try {
    const genres = await Beat.distinct("genre");
    res.json(["all", ...genres]);
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch genres" });
  }
});

// Обработка ошибок
app.use((error, req, res, next) => {
  console.error('Error:', error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({ message: 'File upload error' });
  }
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ message: 'Invalid token' });
  }
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({ message: 'Token expired' });
  }

  res.status(500).json({
    message: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : error.message
  });
});

app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Запуск сервера
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    createDefaultAdmin();
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${NODE_ENV}`);
      console.log(`Frontend URL: ${FRONTEND_URL}`);
      console.log(`Base URL: ${BASE_URL}`);
      console.log(`Health check: http://0.0.0.0:${PORT}/health`);
    });
  })
  .catch((e) => {
    console.error("MongoDB connection error:", e);
    process.exit(1);
  });