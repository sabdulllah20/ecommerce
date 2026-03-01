import express from "express";
import cookieParser from "cookie-parser";
import requestIp from "request-ip";
import { config } from "dotenv";

import { auth } from "./src/routes/auth.route.js";

import { errorHandler } from "./src/middelware/midd_error_hand.js";
import { authorization } from "./src/middelware/midd_auth.js";
import { category } from "./src/routes/category.route.js";
import { product } from "./src/routes/product.js";

const app = express();
config();

app.use(express.json());
app.use(express.static("public"));

app.use(requestIp.mw());
app.use(cookieParser());

app.use(authorization);

app.use("/auth", auth);
app.use("/category", category);
app.use("/product", product);

app.use(errorHandler);

const PORT = process.env.SERVER_PORT;
app.listen(PORT, () => {
  console.log(`Server is running on PORT:${PORT}`);
});
