import express from "express";
import mongoose from "mongoose";
import multer from "multer";
import cors from "cors";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/beats";
const ADMIN_SECRET = process.env.ADMIN_KEY || "defaultSecret";

const app = express();
app.use(cors());
app.use(express.json());

// гарантируем, что папка uploads существует
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// статическая раздача
app.use("/uploads", express.static(uploadsDir));

// подключение к БД
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((e) => console.error("MongoDB error:", e));

// Модель
const Beat = mongoose.model("Beat", {
  title: String,
  genre: String,
  likes: { type: Number, default: 0 },
  plays: { type: Number, default: 0 },
  fileUrl: String,   // '/uploads/xxx.mp3'
  coverUrl: String,  // '/uploads/xxx.jpg'
  date: { type: Date, default: Date.now },
  price: { type: Number, default: 100 },
  featured: { type: Boolean, default: false },
  description: String
});

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Middleware для проверки админ-доступа
function checkAdmin(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
}

// Получение всех битов с возможностью фильтрации по жанру
app.get("/beats", async (req, res) => {
  try {
    const { genre } = req.query;
    let filter = {};

    if (genre && genre !== "all") {
      filter.genre = genre;
    }

    const beats = await Beat.find(filter).sort({ date: -1 });
    res.json(beats);
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch beats" });
  }
});

// Получение одного бита по ID
app.get("/beats/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }
    res.json(beat);
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch beat" });
  }
});

// Создание нового бита (только админ)
app.post("/beats", checkAdmin, upload.fields([{ name: "file" }, { name: "cover" }]), async (req, res) => {
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
    res.json(beat);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to save beat" });
  }
});

// Обновление бита (только админ)
app.put("/beats/:id", checkAdmin, async (req, res) => {
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

    res.json(beat);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to update beat" });
  }
});

// Удаление бита (только админ)
app.delete("/beats/:id", checkAdmin, async (req, res) => {
  try {
    const beat = await Beat.findByIdAndDelete(req.params.id);

    if (!beat) {
      return res.status(404).json({ message: "Beat not found" });
    }

    // Удаляем связанные файлы
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
    console.error(e);
    res.status(500).json({ message: "Failed to delete beat" });
  }
});

// Лайки
app.post("/likes/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });
    beat.likes++;
    await beat.save();
    res.json(beat);
  } catch (e) {
    res.status(500).json({ message: "Failed to like beat" });
  }
});

// Прослушивания
app.post("/plays/:id", async (req, res) => {
  try {
    const beat = await Beat.findById(req.params.id);
    if (!beat) return res.status(404).json({ message: "Beat not found" });
    beat.plays++;
    await beat.save();
    res.json(beat);
  } catch (e) {
    res.status(500).json({ message: "Failed to increment plays" });
  }
});

// Получение списка жанров
app.get("/genres", async (req, res) => {
  try {
    const genres = await Beat.distinct("genre");
    res.json(["all", ...genres]);
  } catch (e) {
    res.status(500).json({ message: "Failed to fetch genres" });
  }
});

// запуск сервера
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend запущен на http://0.0.0.0:${PORT}`);
  console.log(`Локально:   http://localhost:${PORT}`);
  console.log(`В сети LAN: http://<ТВОЙ_IP>:${PORT}`);
});

