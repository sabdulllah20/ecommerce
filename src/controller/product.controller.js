import { sendSuccess } from "../helpers/responseHelper.js";
import { cloudinaryUpload } from "../utility/cloudinary.js";
import fs from "fs";
import { getcategoryId, insertProduct } from "../services/product.service.js";

export const createProduct = async (req, res, next) => {
  try {
    if (!req.user) return sendSuccess(res, 403, "login first");
    // upload to cloudinary
    const result = await cloudinaryUpload(req.file.path);

    const imageUrl = result.secure_url;

    console.log("Cloudinary URL:", imageUrl);

    // delete temp file after upload
    fs.unlinkSync(req.file.path);

    const { category_name, product_name, price, stock } = req.body;
    const categoryId = await getcategoryId(category_name);

    await insertProduct(
      categoryId.category_id,
      product_name,
      price,
      stock,
      req.user.userId,
      imageUrl,
    );
    await sendSuccess(res, 200, "added sucessfully");
  } catch (error) {
    next(error);
  }
};
