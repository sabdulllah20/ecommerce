import { ZodError } from "zod";
import { sendError } from "../helpers/responseHelper.js";

export const errorHandler = (err, req, res, next) => {
  if (err instanceof ZodError) {
    return sendError(res, 400, err.issues[0].message);
  }
  console.error(err);
  return sendError(res, 500, "Interval server error");
};
