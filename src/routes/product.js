import { Router } from "express";
import { createProduct } from "../controller/product.controller.js";
import { upload } from "../middelware/multer.js";
export const product = Router();

product.post("/create", upload.single("image"), createProduct);
