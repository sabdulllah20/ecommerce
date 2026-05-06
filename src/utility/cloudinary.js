// import { v2 as cloudinary } from "cloudinary";
// import fs from "fs";
// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.API_KEY,
//   api_secret: process.env.API_SECRET,
// });

// export const cloudinaryUpload = async function (localFilePath) {
//   try {
//     const uploadResult = await cloudinary.uploader.upload(localFilePath, {
//       resource_type: "auto",
//     });
//     return uploadResult;
//   } catch (error) {
//     fs.unlinkSync(localFilePath);
//     return null;
//   }
// };
import { v2 as cloudinary } from "cloudinary";
import streamifier from "streamifier";
import crypto from "crypto";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

export const cloudinaryUpload = async function (fileBuffer) {
  return new Promise((resolve, reject) => {
    try {
      const uniqueName = crypto.randomBytes(16).toString("hex");

      const stream = cloudinary.uploader.upload_stream(
        {
          resource_type: "auto",
          public_id: uniqueName,
          folder: "products",
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        },
      );

      streamifier.createReadStream(fileBuffer).pipe(stream);
    } catch (error) {
      reject(error);
    }
  });
};
