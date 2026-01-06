import {
  existsEmail,
  saveUser,
  hash,
  generateOtp,
  jwtToken,
  decodeToken,
  deletePendingUser,
  savependingUser,
  existPendingUser,
  jwtTokens,
  verifyHash,
  existsPassword,
  updatePendingUsers,
  savePassword,
  updatePendingUsersOtp,
  saveVerifyToken,
  deleteVerifyTokenByUserId,
  updateTokenAttemptsByUserId,
  jwtTokenForRecoveryEmail,
  findToken,
  saveRecoveryEmail,
  checkRecoveryEmailByUserId,
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
    const otp = generateOtp();
    const otpHash = await hash(otp);

    const user = await savependingUser(
      userName,
      email,
      passwordHash,
      otpHash,
      Date.now() + 20 * 60 * 1000
    );
    //send otp
    await sendMails({
      to: user.email,
      subject: "verification of email",
      html: `here is token = ${otp} for email verification`,
    });

    // send cookie for token verification
    await jwtToken(res, user);
    // response
    return sendSuccess(
      res,
      201,
      "Token is sended expire in 5 mintues,now here we redirect page to confirm token confirmation for email verification "
    );
  } catch (error) {
    next(error);
  }
};

export const confirmTokenAndAddUser = async (req, res, next) => {
  try {
    const { token } = req.body;
    // fetching cookie
    const { verify_email_token } = req.cookies;

    if (!verify_email_token) {
      return sendError(res, 401, "Verification session expired");
    }

    const decode = decodeToken(verify_email_token);
    if (!decode) return sendError(res, 400, "invalid token expire");

    const pendingUser = await existPendingUser(decode.pendingUserId);

    if (!pendingUser)
      return sendError(res, 401, "Verification session expired");

    if (pendingUser.otp_attempt >= 5) {
      await deletePendingUser(pendingUser.email);
      res.clearCookie("verify_email_token");
      return sendError(res, 400, "to many attempts");
    }

    if (Date.now() > pendingUser.otp_expire_at)
      return sendError(res, 400, "token expire");

    const match = await verifyHash(pendingUser.otp_hash, token);
    if (!match) {
      await updatePendingUsers(decode.pendingUserId);
      return sendError(res, 400, "invalid token");
    }
    // user save
    const user = await saveUser(pendingUser.user_name, pendingUser.email);
    // user password save
    await savePassword(user.user_id, pendingUser.password_hash);
    // pending user delete
    await deletePendingUser(pendingUser.email);
    // cookie clear
    res.clearCookie("verify_email_token");
    return sendSuccess(res, 200, "user is created sucessfully");
  } catch (error) {
    next(error);
  }
};

export const resendTokenForEmailVerification = async (req, res, next) => {
  try {
    const { verify_email_token } = req.cookies;
    const decode = decodeToken(res, verify_email_token);
    const user = await existPendingUser(decode.pendingUserId);
    const otp = generateOtp();
    const otpHash = await hash(otp);
    await updatePendingUsersOtp(decode.pendingUserId, otpHash);
    sendMails({
      to: user.email,
      subject: "email verification",
      html: `here is token = ${otp} for email verification`,
    });
    return sendSuccess(res, 200, "token is sended");
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

export const sendTokenOnRecoveryEmail = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "login first");
    const { email } = req.body;
    const alreadyEmail = await checkRecoveryEmailByUserId(req.user.userId);
    if (alreadyEmail) return sendError(res, 400, "already email is exists");
    const otp = generateOtp();
    const otpHash = await hash(otp);
    await deleteVerifyTokenByUserId(req.user.userId);
    await saveVerifyToken(req.user.userId, otpHash);
    sendMails2({
      to: email,
      subject: "Verification for recovery email",
      html: `${otp}`,
    });
    jwtTokenForRecoveryEmail(res, req.user.userId, email);
    return sendSuccess(res, 200, "token is sended to recovery email");
  } catch (error) {
    next(error);
  }
};

export const confirmTokenAddRecoveryEmail = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "login first");
    const COOKIE_OPTIONS = {
      httpOnly: true,
      secure: false,
      path: "/auth/recovery-email/verify",
    };
    const { token } = req.body;
    const { recovery_email_verify } = req.cookies;

    if (!recovery_email_verify) {
      await deleteVerifyTokenByUserId(req.user.userId);
      return sendError(res, 400, "Invalid Token And Session Expiry Try Again");
    }

    const decode = decodeToken(recovery_email_verify);

    const tokenRecord = await findToken(req.user.userId);
    if (new Date() > tokenRecord.otp_expire_at) {
      await deleteVerifyTokenByUserId(req.user.userId);
      res.clearCookie("recovery_email_verify");
      return sendError(res, 400, "Invalid Token And Session Expiry Try Again");
    }

    if (tokenRecord.otp_attempt >= 5) {
      await deleteVerifyTokenByUserId(req.user.userId);
      res.clearCookie("recovery_email_verify");
      return sendError(res, 429, "Too many attempts");
    }

    const match = await verifyHash(tokenRecord.otp_hash, token);
    if (!match) {
      await updateTokenAttemptsByUserId(req.user.userId);
      return sendError(res, 400, "Invalid Token");
    }

    await saveRecoveryEmail(req.user.userId, decode.recoveryEmail);
    await deleteVerifyTokenByUserId(req.user.userId);

    res.clearCookie("recovery_email_verify", COOKIE_OPTIONS);

    return sendSuccess(res, 200, "recovery email is added");
  } catch (error) {
    next(error);
  }
};

export const sendTokenOnRecoveryEmailForPass = async (req, res, next) => {
  try {
    const { email } = req.body;

    // check email
    const user = await existsEmail(email);
    if (!user)
      return sendError(
        res,
        400,
        "If the email is valid, you will receive a token for email verification"
      );
    const otp = generateOtp();
    const otpHash = await hash(otp);
    await deleteVerifyTokenByUserId(user.user_id);
    await saveVerifyToken(user.user_id, otpHash);
    sendMails2({
      to: user.email,
      subject: "token for new password ",
      html: `${otp}`,
    });
    return sendSuccess(res, 200, "token is sended to your email");
  } catch (error) {
    next(error);
  }
};

export const confirmTokenForPassChange = async (req, res, next) => {
  try {
    const { token } = req.body;
    const { recovery_email_verify } = req.cookies;

    if (!recovery_email_verify) {
      await deleteVerifyTokenByUserId(req.user.userId);
      return sendError(res, 400, "Invalid Token And Session Expiry Try Again");
    }

    const decode = decodeToken(recovery_email_verify);

    const tokenHash = await findToken(req.user.userId);
    if (Date.now() > tokenHash.otp_expire_at) {
      await deleteVerifyTokenByUserId(req.user.userId);
      return sendError(res, 400, "Invalid Token And Session Expiry Try Again");
    }
    const match = await verifyHash(tokenHash.otp_hash, token);
    if (!match) {
      await updateTokenAttemptsByUserId(req.user.userId);
      return sendError(res, 400, "Invalid Token");
    }
    await saveRecoveryEmail(req.user.userId, decode.recoveryEmail);
    await deleteVerifyTokenByUserId(req.user.userId);
    res.clearCookie("recovery_email_verify");
    return sendSuccess(res, 200, "recovery email is added ");
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
