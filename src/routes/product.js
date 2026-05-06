import { Router } from "express";
import {
  addToCart,
  allProduct,
  createProduct,
  addToCartIncrease,
  removeCart,
  CartData,
} from "../controller/product.controller.js";
import { upload } from "../middelware/multer.js";
export const product = Router();

product.post("/create", upload.array("image", 5), createProduct);
product.get("/show", allProduct);

product.post("/cart/item", addToCart);
product.get("/cart", CartData);
product.patch("/cart/item/increase/:product_id", addToCartIncrease);
product.post("/cart/item/remove/:product_id", removeCart);
