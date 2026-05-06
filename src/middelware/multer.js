// import multer from "multer";
// import path from "path";
// import crypto from "crypto";

// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     cb(null, "./public");
//   },
//   filename: function (req, file, cb) {
//     console.log(file);
//     const name = crypto.randomBytes(12).toString("hex");
//     const ext = path.extname(file.originalname);
//     cb(null, name + ext);
//   },
// });

// export const upload = multer({
//   storage: multer.memoryStorage,
//   fileFilter: (req, file, cb) => {
//     const allowTypes = ["image/jpeg", "image/png", "image/webp"];

//     if (allowTypes.includes(file.mimetype)) cb(null, true);
//     else cb(new Error("only jpeg file is require "), false);
//   },
//   limits: { fileSize: 5 * 1024 * 1024 },
// });
import multer from "multer";

export const upload = multer({
  storage: multer.memoryStorage(),

  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPEG, PNG, WEBP images are allowed"), false);
    }
  },

  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});
