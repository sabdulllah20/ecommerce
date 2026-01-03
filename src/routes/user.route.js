import { Router } from "express";
import {
  checkEmailExist,
  userRegisteration,
  enterVerificationTokenForEmail,
  userLogin,
  userLogout,
  resendCode,
} from "../controller/user.controller.js";
export const routes = Router();

routes.post("/email-check", checkEmailExist);
routes.post("/register", userRegisteration);
routes.post("/verify/email/confirm", enterVerificationTokenForEmail);
routes.post("/verify/email/resend", resendCode);
routes.post("/login", userLogin);
routes.post("/logout", userLogout);
