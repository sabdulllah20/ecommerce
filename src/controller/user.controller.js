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
  updateUserValid,
  jwtTokens,
  verifyHash,
  existsPassword,
  updateUserLogged,
  updateUserLoggedOut,
  updatePendingUsers,
  savePassword,
} from "../services/user.service.js";
import { sendError, sendSuccess } from "../helpers/responseHelper.js";
import { sendMails } from "../lib/resend.js";

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

export const userRegisteration = async (req, res, next) => {
  try {
    const { userName, email, password } = req.body;

    // checking
    // const alreadyExistEmail = await existsPendingEmails(email);
    // if (alreadyExistEmail)
    //   return sendError(
    //     res,
    //     400,
    //     "If the email is valid, you will receive a verification email"
    //   );

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
      html: `Token = ${otp} 
      This token is expire in 5 minutes
      `,
    });

    // send cookie for token verification
    await jwtToken(res, user);
    // response
    return res.send(otp);
    return sendSuccess(
      res,
      201,
      "Token is sended expire in 5 mintues,now here we redirect page to confirm token confirmation for email verification "
    );
  } catch (error) {
    next(error);
  }
};

export const enterVerificationTokenForEmail = async (req, res, next) => {
  try {
    const { token } = req.body;

    // fetching cookie
    const { verify_email_token } = req.cookies;

    if (!verify_email_token) {
      return sendError(res, 401, "Verification session expired");
    }

    const decode = decodeToken(res, verify_email_token);
    if (!decode) return sendError(res, 400, "invalid token expire");

    // checking cookie
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
    const user = await saveUser(pendingUser.user_name, pendingUser.email);
    await savePassword(user.user_id, pendingUser.password_hash);
    await updateUserValid(user.user_id);
    await deletePendingUser(pendingUser.email);
    res.clearCookie("verify_email_token");
    return sendSuccess(res, 200, "user is created sucessfully");
  } catch (error) {
    next(error);
  }
};

// export const sendVerificationTokenForMobileNo = async (req, res, next) => {
//   try {
//     const { countryCode, phoneNo } = req.body;
//     const { verify_email_token } = req.cookies;
//     const decode = decodeToken(res, verify_email_token);
//     const alreadyExistPhoneNo = await existsPhoneNo(countryCode, phoneNo);
//     if (alreadyExistPhoneNo)
//       return sendError(
//         res,
//         400,
//         "If the phone no is valid, you will receive a verification phone no"
//       );

//     await insertPasswordInPendingUser(
//       decode.pendingUserId,
//       countryCode,
//       phoneNo
//     );

//     const user = await saveUser(decode.user_name, decode.email);
//     await savePassword(user.user_id, pendingUser.password_hash);
//     await updateUserValid(user.user_id);
//     res.clearCookie("verify_email_token");
//     await deletePendingUser(pendingUser.email);
//     return sendSuccess(res, 200, "user is created sucessfully");

// const otp = generateOtp();
// const otpHash = hash(otp);
// await updatePendingUserOtp(
//   decode.pendingUserId,
//   otpHash,
//   Date.now() + 20 * 60 * 10000
// );

// sendSuccess(res, 200, "token is sended ");
//   } catch (error) {
//     next(error);
//   }
// };
// export const enterVerificationTokenForMobileNo = async (req, res, next) => {
//   try {
//     const { token } = req.body;
//     const { verify_email_token } = req.cookies;
//     if (!verify_email_token) return sendError(res, 400, "token expire");
//     const decode = decodeToken(verify_email_token);
//     const pendingUser = await existPendingUser(decode.pendingUserId);
//     if (pendingUser.otp_expire_at < Date.now())
//       return sendError(res, 400, "token expire");
//     if (pendingUser.otp_attempt >= 5) {
//       await deletePendingUser(pendingUser.email);
//       return sendError(res, 400, "token expire and try again");
//     }
//     const match = verifyHash(pendingUser.otp_hash, token);
//     if (!match) {
//       await updatePendingUsers(pendingUser.pending_user_id);
//       return sendError(res, 400, `invalid token`);
//     }
//     const user = await saveUser(pendingUser.user_name, pendingUser.email);
//     await savePassword(user.user_id, pendingUser.password_hash);
//     updateUserValid(user.user_id);
//     res.clearCookie("verify_email_token");
//     await deletePendingUser(pendingUser.email);
//     return sendSuccess(res, 200, "verify success");
//   } catch (error) {
//     next(error);
//   }
// };

export const userLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const rows = await existsEmail(email);

    if (!rows) return sendError(res, 400, "invalid email password");

    const passwordHash = await existsPassword(rows.user_id);
    const match = await verifyHash(passwordHash.password_hash, password);
    if (!match) return sendError(res, 400, "invalid email password");
    await jwtTokens(req, res, rows);
    await updateUserLogged(rows.user_id);
    return sendSuccess(res, 200, "User login successfully");
  } catch (error) {
    next(error);
  }
};

export const userLogout = async (req, res, next) => {
  try {
    if (!req.user) return sendError(res, 400, "already logout");
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    await updateUserLoggedOut(req.user.userId);
    sendSuccess(res, 200, "logout successfully");
  } catch (error) {
    next(error);
  }
};
