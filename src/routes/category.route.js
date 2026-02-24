import { Router } from "express";
import { addCategory } from "../controller/category.controller.js";

export const category = Router();

category.post("/add", addCategory);
