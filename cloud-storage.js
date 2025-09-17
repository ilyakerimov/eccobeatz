import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import fs from "fs";

// Кастомный middleware для установки правильного x-amz-content-sha256
const contentSha256Middleware = (next) => async (args) => {
  if (args.request?.headers?.['x-amz-content-sha256'] === 'STREAMING-UNSIGNED-PAYLOAD-TRAILER') {
    args.request.headers['x-amz-content-sha256'] = 'UNSIGNED-PAYLOAD';
  }
  return next(args);
};

const s3Client = new S3Client({
  endpoint: process.env.S3_ENDPOINT || "https://hb.ru-msk.vkcs.cloud",
  region: process.env.S3_REGION || "ru-msk",
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
  },
  middleware: {
    pre: [contentSha256Middleware]
  }
});

const BUCKET_NAME = process.env.S3_BUCKET_NAME;

export async function uploadToCloudStorage(filePath, key, contentType) {
  try {
    const fileBuffer = fs.readFileSync(filePath);

    const uploadParams = {
      Bucket: BUCKET_NAME,
      Key: key,
      Body: fileBuffer,
      ContentType: contentType,
      ACL: 'public-read'
    };

    const command = new PutObjectCommand(uploadParams);
    await s3Client.send(command);

    return key;
  } catch (error) {
    console.error("Error uploading to cloud storage:", error);
    throw error;
  }
}

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

export function getCloudStorageUrl(key) {
  if (!key) return null;
  const endpoint = process.env.S3_ENDPOINT || "https://hb.ru-msk.vkcs.cloud";
  return `${endpoint}/${BUCKET_NAME}/${key}`;
}