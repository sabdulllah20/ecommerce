import { pool } from "../database/postgreSql.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { config } from "dotenv";
import crypto from "crypto";
import { sendError } from "../helpers/responseHelper.js";
config();

const secretKey = process.env.JWT_SECRET_KEY;

export const existsPendingEmails = async (email) => {
  const { rows } = await pool.query(
    `
    select * from pending_users
    where email = $1
    `,
    [email]
  );
  return rows[0];
};

export const deletePendingUser = async (email) => {
  return await pool.query(
    `
    delete from pending_users
    where email = $1
    `,
    [email]
  );
};

export const savependingUser = async (
  verificationId,
  userName,
  email,
  passwordHash,
  otpHash
) => {
  const { rows } = await pool.query(
    `
    insert into  pending_users
    (verification_id,user_name,email,password_hash,otp_hash)
    values($1,$2,$3,$4,$5)
    returning *
    `,
    [verificationId, userName, email, passwordHash, otpHash]
  );
  return rows[0];
};

export const existsEmail = async (email) => {
  const { rows } = await pool.query(
    `
    select * from users 
    where email = $1
    `,
    [email]
  );
  return rows[0];
};

export const saveUser = async (userName, email) => {
  const { rows } = await pool.query(
    `
    insert into users
    (user_name,email,valid_email)
    values($1,$2,true)  
    returning *  
    `,
    [userName, email]
  );
  return rows[0];
};

export const hash = async (data) => {
  return await argon2.hash(String(data));
};

export const savePassword = async (userId, passwordHash) => {
  await pool.query(
    `
    insert into users_passwords
    (user_id,password_hash)
    values($1,$2)
    
    `,
    [userId, passwordHash]
  );
};

export const existsPassword = async (userId) => {
  const { rows } = await pool.query(
    `
    select * from users_passwords
    where user_id = $1
    `,
    [userId]
  );
  return rows[0];
};

export const verifyHash = async (hashData, stringData) => {
  return await argon2.verify(hashData, stringData);
};

export const insertToken = async (otp) => {
  const { rows } = await pool.query(
    `
    insert into  pending_users
    otp_hash = $1
    returning *
    `,
    [otp]
  );
  return rows[0];
};

export const saveVerifyToken = async (verificationId, userId, otpHash) => {
  return await pool.query(
    `
    insert into email_verification_tokens
    (verification_id,user_id,otp_hash)
    values($1,$2,$3)

    `,
    [verificationId, userId, otpHash]
  );
};

export const deleteVerifyToken = async (userId) => {
  return await pool.query(
    `
    delete from email_verification_tokens
    where user_id = $1
    `,
    [userId]
  );
};

export const userToken = async (userId) => {
  const { rows } = await pool.query(
    `
    select * from pending_users
    where user_id = $1
    `,
    [userId]
  );
  return rows[0];
};

export const jwtToken = async (res, user) => {
  const payload = {
    pendingUserId: user.pending_user_id,
  };
  const token = jwt.sign(payload, secretKey, { expiresIn: 5 * 60 });
  res.cookie("verify_email_token", token, {
    httpOnly: false,
    secure: false,
    sameSite: "lax",
    maxAge: 5 * 60 * 1000,
    path: "/auth/verify",
  });
};

export const updatePendingUsers = async (userId) => {
  await pool.query(
    `
    update pending_users
    set otp_attempt = otp_attempt + 1
    where pending_user_id = $1
    `,
    [userId]
  );
};

export const generateAccessToken = (payload) => {
  return jwt.sign(payload, secretKey, { expiresIn: 15 * 60 });
};

export const generateRefreshToken = (payload) => {
  return jwt.sign(payload, secretKey, { expiresIn: 7 * 24 * 60 * 60 });
};

export const clearSession = async (userId) => {
  return await pool.query(
    `
    delete from sessions
    where user_id = $1
    `,
    [userId]
  );
};

export const createSession = async (userId, userAgent, ip) => {
  const { rows } = await pool.query(
    `
    insert into sessions (user_id,user_agent,ip)
    values($1,$2,$3)
    returning *
    `,
    [userId, userAgent, ip]
  );

  return rows[0];
};

export const jwtTokens = async (req, res, user) => {
  await clearSession(user.user_id);
  const session = await createSession(
    user.user_id,
    req.headers["user-agent"],
    req.clientIp
  );

  const payload = {
    userId: user.user_id,
    userName: user.user_name,
    email: user.email,
    isEmailValid: user.valid_email,
    sessionId: session.session_id,
  };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken({ sessionId: session.session_id });

  res.cookie("accessToken", accessToken, {
    httpOnly: false,
    secure: false,
    maxAge: 15 * 60 * 1000,
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: false,
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

export const decodeToken = (token) => {
  return jwt.verify(token, secretKey);
};

export const findSession = async (sessionId) => {
  const { rows } = await pool.query(
    `
      select * from sessions
      where session_id = $1
    `,
    [sessionId]
  );
  return rows[0];
};

export const findUser = async (userId) => {
  const { rows } = await pool.query(
    `
  select * from users 
  where user_id = $1    
    `,
    [userId]
  );
  return rows[0];
};

export const refreshTokens = async (refreshToken, next) => {
  try {
    const decode = decodeToken(refreshToken);

    const session = await findSession(decode.sessionId);
    const user = await findUser(session.user_id);
    const payload = {
      userId: user.user_id,
      userName: user.user_name,
      email: user.email,
      isEmailValid: user.valid_email,
      sessionId: session.session_id,
    };
    const newAccessToken = generateAccessToken(payload);
    const newRefreshToken = generateRefreshToken({
      sessionId: session.session_id,
    });

    return { newAccessToken, newRefreshToken, userInfo: payload };
  } catch (error) {
    next(error);
  }
};

export const userByOnlyId = async (userId) => {
  const { rows } = await pool.query(
    `
    select * from users 
    where user_id = $1
    
    `,
    [userId]
  );
  return rows[0];
};

export const deleteVerifyTokenByUserId = async (userId) => {
  return await pool.query(
    `
    delete from email_verification_tokens
    where user_id = $1
    `,
    [userId]
  );
};

export const findToken = async (token) => {
  const { rows } = await pool.query(
    `
    select * from email_verification_tokens
    where otp_hash = $1
    `,
    [token]
  );
  return rows[0];
};

export const updateTokenAttemptsByUserId = async (userId) => {
  return await pool.query(
    `
    update email_verification_tokens
    set otp_attempt = otp_attempt + 1
    where user_id = $1 
    `,
    [userId]
  );
};

//////////////////////////////////////////////
export const generateRandomToken = (digit) => {
  const min = 10 ** (digit - 1);
  const max = 10 ** digit;
  const token = crypto.randomInt(min, max).toString();
  console.log(token);
  return token;
};

export const generateRandomTokenHash = (token) => {
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  return hash;
};

export const existToken = async (token) => {
  const { rows } = await pool.query(
    `
    select * from pending_users
    where otp_hash = $1
    `,
    [token]
  );
  return rows[0];
};

export const generateRandomUUID = () => {
  return crypto.randomUUID();
};

export const updatePendingUsersAttempts = async (verificationId) => {
  return await pool.query(
    `
    update pending_users
    set otp_attempt = otp_attempt + 1
    where verification_id = $1
    `,
    [verificationId]
  );
};
export const deletePendingUserById = async (verificationId) => {
  return await pool.query(
    `
      delete from pending_users
    where verification_id = $1
    `,
    [verificationId]
  );
};

export const findPendingUserById = async (verificationId) => {
  const { rows } = await pool.query(
    `
    select * from pending_users
    where verification_id = $1
    `,
    [verificationId]
  );
  return rows[0];
};

export const updatePendingUsersOtpForResend = async (
  verificationId,
  otpHash
) => {
  return await pool.query(
    `
    update pending_users
    set otp_hash = $1,
    otp_expire_at = current_timestamp + interval '10 minutes'
    where verification_id = $2
    `,
    [otpHash, verificationId]
  );
};

export const findTokenById = async (verificationId) => {
  const { rows } = await pool.query(
    `
    select * from email_verification_tokens
    where verification_id = $1
    `,
    [verificationId]
  );
  return rows[0];
};

export const updatePassword = async (userId, passwordHash) => {
  return await pool.query(
    `
    update users_passwords
    set  password_hash = $1,
    password_updated_at=current_timestamp
    where user_id = $2
    
    `,
    [passwordHash, userId]
  );
};
