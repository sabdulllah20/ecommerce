import { Router } from "express";
import {
  checkEmailExist,
  sendTokenOnEmailVerification,
  resendTokenForEmailVerification,
  userLogin,
  sendTokenOnRecoveryEmail,
  confirmTokenAndAddUser,
  confirmTokenAddRecoveryEmail,
  sendTokenOnRecoveryEmailForPass,
  userLogout,
} from "../controller/user.controller.js";
export const routes = Router();

routes.post("/auth/email/check", checkEmailExist);
routes.post("/auth/register", sendTokenOnEmailVerification);
routes.post("/auth/verify/email", confirmTokenAndAddUser);
routes.post("/auth/verify/email/resend", resendTokenForEmailVerification);
routes.post("/auth/login", userLogin);
routes.post("/auth/recovery-email/add", sendTokenOnRecoveryEmail);
routes.post("/auth/recovery-email/verify", confirmTokenAddRecoveryEmail);
routes.post("/auth/password/forgot", sendTokenOnRecoveryEmailForPass);
routes.post("/auth/logout", userLogout);
