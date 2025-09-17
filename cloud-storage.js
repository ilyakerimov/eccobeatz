import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import fs from "fs";
import { fromIni } from "@aws-sdk/credential-provider-ini";

// Конфигурация для Mail.ru Cloud Solutions (VK Cloud)
const s3Client = new S3Client({
  endpoint: process.env.S3_ENDPOINT || "https://hb.ru-msk.vkcs.cloud",
  region: process.env.S3_REGION || "ru-msk",
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
  }
});

const BUCKET_NAME = process.env.S3_BUCKET_NAME;

// Функция для загрузки файла в облачное хранилище
export async function uploadToCloudStorage(filePath, key, contentType) {
  try {
    const fileStream = fs.createReadStream(filePath);

    const uploadParams = {
      Bucket: BUCKET_NAME,
      Key: key,
      Body: fileStream,
      ContentType: contentType,
      ACL: 'public-read'
    };

    const command = new PutObjectCommand(uploadParams);
    await s3Client.send(command);

    return key; // Возвращаем ключ файла в хранилище
  } catch (error) {
    console.error("Error uploading to cloud storage:", error);
    throw error;
  }
}

// Функция для удаления файла из облачного хранилища
export async function deleteFromCloudStorage(key) {
  try {
    const deleteParams = {
      Bucket: BUCKET_NAME,
      Key: key
    };

    const command = new DeleteObjectCommand(deleteParams);
    await s3Client.send(command);

    return true;
  } catch (error) {
    console.error("Error deleting from cloud storage:", error);
    throw error;
  }
}

// Функция для получения URL файла в облачном хранилище
export function getCloudStorageUrl(key) {
  if (!key) return null;

  // Формируем URL для VK Cloud Storage
  const endpoint = process.env.S3_ENDPOINT || "https://hb.ru-msk.vkcs.cloud";
  return `${endpoint}/${BUCKET_NAME}/${key}`;
}