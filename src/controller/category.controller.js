import { sendError, sendSuccess } from "../helpers/responseHelper.js";
import { createCategory, existCategory } from "../services/category.service.js";

export const addCategory = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 403, "login first");
    if (req.user.role !== "admin")
      return sendError(res, 403, "only admin can add category");
    const { categoryName } = req.body;
    const checkCategory = await existCategory(categoryName);
    if (checkCategory) return sendError(res, 400, "already exist category");
    await createCategory(categoryName);
    sendSuccess(res, 200, "created success");
  } catch (error) {
    next(error);
  }
};
