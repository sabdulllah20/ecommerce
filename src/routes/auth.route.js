import { Router } from "express";
import {
  checkEmailExist,
  sendTokenOnEmailVerification,
  resendTokenForEmailVerification,
  userLogin,
  confirmTokenAndAddUser,
  sendTokenOnRecoveryEmailForPass,
  userLogout,
  confirmTokenForForgotPassChange,
  resetForgotPass,
} from "../controller/user.controller.js";
export const auth = Router();

auth.post("/email/check", checkEmailExist);
auth.post("/register", sendTokenOnEmailVerification);
auth.post("/verify/email", confirmTokenAndAddUser);
auth.post("/verify/email/resend", resendTokenForEmailVerification);
auth.post("/login", userLogin);
auth.post("/password/forgot", sendTokenOnRecoveryEmailForPass);
auth.post("/password/forgot/verify", confirmTokenForForgotPassChange);
auth.post("/password/forgot/reset", resetForgotPass);
auth.post("/logout", userLogout);
