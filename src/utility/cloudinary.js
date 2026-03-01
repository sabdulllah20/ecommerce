import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
cloudinary.config({
  cloud_name: "dj6ivsjr4",
  api_key: "836384222872846",
  api_secret: "fn4AO6vhVWH8myONihPV9BJb2jA",
  // cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  // api_key: process.env.API_KEY,
  // api_secret: process.env.API_SECRET,
});

export const cloudinaryUpload = async function (localFilePath) {
  try {
    const uploadResult = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    return uploadResult;
  } catch (error) {
    fs.unlinkSync(localFilePath);
    return null;
  }
};
