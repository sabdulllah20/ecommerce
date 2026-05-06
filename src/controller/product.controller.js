import { sendError, sendSuccess } from "../helpers/responseHelper.js";
import { cloudinaryUpload } from "../utility/cloudinary.js";
import {
  deleteCart,
  existCart,
  existProduct,
  getCartData,
  getcategoryId,
  getingProduct,
  insertFileInfo,
  insertProduct,
  modifyeData,
  saveCart,
  saveCartData,
  updateQuantityProduct,
} from "../services/product.service.js";

export const createProduct = async (req, res, next) => {
  try {
    if (!req.user) return sendSuccess(res, 403, "login first");

    const { category_name, product_name, price, stock } = req.body;

    const categoryId = await getcategoryId(category_name);

    const product = await insertProduct(
      categoryId.category_id,
      product_name,
      price,
      stock,
      req.user.userId,
    );

    for (const file of req.files) {
      const result = await cloudinaryUpload(file.buffer);
      const fileUrl = result.secure_url;
      await insertFileInfo(product.product_id, fileUrl);
    }

    await sendSuccess(res, 200, "added sucessfully");
  } catch (error) {
    next(error);
  }
};

export const allProduct = async (req, res, next) => {
  try {
    // if (!req.user) return sendError(res, 401, "login first");
    const result = await getingProduct();
    sendSuccess(res, 201, "product", Object.values(result));
  } catch (error) {
    next(error);
  }
};

export const addToCart = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 200, "login first");

    const { product_id, quantity } = req.body;

    let cartData = await existCart(req.user.userId);

    if (!cartData) {
      cartData = await saveCart(req.user.userId);
    }
    let check = await existProduct(product_id, cartData.cart_id);
    if (check) return sendError(res, 400, "already added to cart");
    await saveCartData(cartData.cart_id, product_id, quantity);

    sendSuccess(res, 200, "ok");
  } catch (error) {
    next(error);
  }
};

export const CartData = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "login first");
    const cart = await existCart(req.user.userId);
    if (!cart) return sendError(res, 400, "no product is added to cart ");

    const result = await getCartData(cart.cart_id);

    const data = modifyeData(result);
    console.log(data);

    sendSuccess(res, 200, "ok", data);
  } catch (error) {
    next(error);
  }
};

export const addToCartIncrease = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "login first");
    let { product_id } = req.params;
    const { change } = req.body;

    let cart = await existCart(req.user.userId);
    await updateQuantityProduct(cart.cart_id, Number(product_id), change);

    sendSuccess(res, 200, "ok");
  } catch (error) {
    next(error);
  }
};

export const removeCart = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "login first");

    const { product_id } = req.params;
    const cart = await existCart(req.user.userId);

    const result = await deleteCart(cart.cart_id, product_id);
    if (!result) return sendError(res, 400, "already deleted");
    sendSuccess(res, 200, "ok");
  } catch (error) {
    next(error);
  }
};
