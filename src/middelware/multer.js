import multer from "multer";
import path from "path";
import crypto from "crypto";
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/temp");
  },
  filename: function (req, file, cb) {
    const name = crypto.randomBytes(12).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, name + ext);
  },
});

export const upload = multer({ storage: storage });
