import {
  existsEmail,
  saveUser,
  hash,
  deletePendingUser,
  savependingUser,
  jwtTokens,
  verifyHash,
  existsPassword,
  savePassword,
  saveVerifyToken,
  deleteVerifyTokenByUserId,
  updateTokenAttemptsByUserId,
  findToken,
  generateRandomToken,
  generateRandomTokenHash,
  existToken,
  generateRandomUUID,
  updatePendingUsersAttempts,
  deletePendingUserById,
  findPendingUserById,
  updatePendingUsersOtpForResend,
  findTokenById,
  updatePassword,
} from "../services/user.service.js";
import { sendError, sendSuccess } from "../helpers/responseHelper.js";
import { sendMails, sendMails2 } from "../lib/resend.js";

// registration

export const checkEmailExist = async (req, res, next) => {
  try {
    const { email } = req.body;
    const rows = await existsEmail(email);
    if (rows)
      return sendError(
        res,
        400,
        "If the email is valid, you will receive a verification email"
      );
    return sendSuccess(res, 200, "now here we redirect to the register page");
  } catch (error) {
    next(error);
  }
};

export const sendTokenOnEmailVerification = async (req, res, next) => {
  try {
    const { userName, email, password } = req.body;

    await deletePendingUser(email);

    const passwordHash = await hash(password);

    // generate otp
    const otp = generateRandomToken(8);
    const otpHash = generateRandomTokenHash(otp);
    const verificationId = generateRandomUUID();

    const user = await savependingUser(
      verificationId,
      userName,
      email,
      passwordHash,
      otpHash
    );
    //send otp
    await sendMails({
      to: user.email,
      subject: "verification of email",
      html: `here is token = ${otp} for email verification`,
    });

    // response
    return sendSuccess(
      res,
      201,
      "Token is sended expire in 5 mintues,now here we redirect page to confirm token confirmation for email verification ",
      verificationId + " " + otp
    );
  } catch (error) {
    next(error);
  }
};

export const confirmTokenAndAddUser = async (req, res, next) => {
  try {
    const { token, verificationId } = req.body;
    const otpHash = generateRandomTokenHash(token);
    const tokenRecord = await existToken(otpHash);

    const pendingUser = await findPendingUserById(verificationId);

    if (pendingUser.otp_expire_at < new Date()) {
      await deletePendingUserById(verificationId);
      return sendError(res, 400, "token is expire try again for fresh");
    }
    if (pendingUser.otp_attempt >= 5) {
      await deletePendingUserById(verificationId);
      return sendError(res, 400, "to many attempts");
    }
    if (!tokenRecord) {
      await updatePendingUsersAttempts(verificationId);
      return sendError(res, 400, "invalid Token");
    }

    // user save
    const user = await saveUser(pendingUser.user_name, pendingUser.email);
    // user password save
    await savePassword(user.user_id, pendingUser.password_hash);
    // pending user delete
    await deletePendingUser(pendingUser.email);

    return sendSuccess(res, 200, "user is created sucessfully");
  } catch (error) {
    next(error);
  }
};

export const resendTokenForEmailVerification = async (req, res, next) => {
  try {
    const { verificationId } = req.body;
    const pendingUser = await findPendingUserById(verificationId);

    const otp = generateRandomToken(8);
    const otpHash = generateRandomTokenHash(otp);

    console.log(otp);
    console.log(otpHash);

    await updatePendingUsersOtpForResend(verificationId, otpHash);

    sendMails({
      to: pendingUser.email,
      subject: "email verification",
      html: `here is token = ${otp} for email verification`,
    });
    return sendSuccess(res, 200, "token is sended", otp);
  } catch (error) {
    next(error);
  }
};

export const userLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const rows = await existsEmail(email);

    if (!rows) return sendError(res, 400, "invalid email password");

    const passwordHash = await existsPassword(rows.user_id);
    const match = await verifyHash(passwordHash.password_hash, password);
    if (!match) return sendError(res, 400, "invalid email password");
    await jwtTokens(req, res, rows);
    return sendSuccess(res, 200, "User login successfully");
  } catch (error) {
    next(error);
  }
};

export const sendTokenOnRecoveryEmailForPass = async (req, res, next) => {
  try {
    if (req.user)
      return sendError(res, 400, "already login no need to forgot password");
    const { email } = req.body;

    // check email
    const user = await existsEmail(email);
    if (!user)
      return sendError(
        res,
        400,
        "If the email is valid, you will receive a token for email verification"
      );

    const otp = generateRandomToken(8);
    const otpHash = generateRandomTokenHash(otp);
    const verificationId = generateRandomUUID();

    await deleteVerifyTokenByUserId(user.user_id);

    await saveVerifyToken(verificationId, user.user_id, otpHash);

    sendMails2({
      to: email,
      subject: "token for new password ",
      html: `${otp}`,
    });

    return sendSuccess(
      res,
      200,
      "If the email is valid, a verification token has been sent",
      verificationId + " " + otp
    );
  } catch (error) {
    next(error);
  }
};

export const confirmTokenForForgotPassChange = async (req, res, next) => {
  try {
    if (req.user)
      return sendError(res, 400, "already login no need to forgot password");

    const { token, verificationId } = req.body;
    const tokenHash = generateRandomTokenHash(token);
    console.log(tokenHash);

    const tokenRecord = await findToken(tokenHash);
    console.log(tokenRecord);
    const tokenData = await findTokenById(verificationId);
    console.log(tokenData);
    // expiry check
    if (new Date() > tokenData.otp_expire_at) {
      await deleteVerifyTokenByUserId(tokenData.user_id);
      return sendError(res, 400, "token is expire");
    }

    // max attempt
    if (tokenData.otp_attempt >= 5) {
      await deleteVerifyTokenByUserId(tokenData.user_id);
      return sendError(res, 400, "token is expire ");
    }

    // verify token
    if (!tokenRecord) {
      await updateTokenAttemptsByUserId(tokenData.user_id);
      return sendError(res, 400, "invalid token");
    }

    return sendSuccess(
      res,
      200,
      "If the token is valid, you receive the password change page"
    );
  } catch (error) {
    next(error);
  }
};

export const resetForgotPass = async (req, res, next) => {
  try {
    const { newPassword, confirmPassword, verificationId } = req.body;
    if (newPassword !== confirmPassword)
      return sendError(res, 400, "both password dont match");
    const passwordHash = await hash(newPassword);
    const user = await findTokenById(verificationId);
    await updatePassword(user.user_id, passwordHash);
    await deleteVerifyTokenByUserId(user.user_id);
    return sendSuccess(res, 200, "password is updated success");
  } catch (error) {
    next(error);
  }
};

export const userLogout = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "already logout");
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    sendSuccess(res, 200, "logout successfully");
  } catch (error) {
    next(error);
  }
};
