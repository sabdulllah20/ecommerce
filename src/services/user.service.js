import { pool } from "../database/postgreSql.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { config } from "dotenv";
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
export const existPendingUser = async (pendingUserId) => {
  const { rows } = await pool.query(
    `
  select * from pending_users
  where pending_user_id=$1
  `,
    [pendingUserId]
  );
  return rows[0];
};

export const savependingUser = async (
  userName,
  email,
  passwordHash,
  otpHash,
  otpExpiry
) => {
  const { rows } = await pool.query(
    `
    insert into  pending_users
    (user_name,email,password_hash,otp_hash,otp_expire_at)
    values($1,$2,$3,$4,$5)
    returning *
    `,
    [userName, email, passwordHash, otpHash, otpExpiry]
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

export const checkEmailByUserEmail = async (email, userId) => {
  const { rows } = await pool.query(
    `
    select * from users 
    where user_id = $1 and email =$2 
    `,
    [userId, email]
  );
  return rows[0];
};

export const deleteUse = async (userId) => {
  return await pool.query(
    `
    delete from  users
    where user_id = $1
    `,
    [userId]
  );
};

export const generateOtp = () => {
  const token = Math.floor(Math.random() * 100000000);
  return token;
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

export const updateUserValid = async (userId) => {
  return await pool.query(
    `
    update users 
    set 
    valid_email = true ,
    user_updated_at = current_timestamp
    where user_id = $1
    `,
    [userId]
  );
};

export const updateUserLogged = async (userId) => {
  return await pool.query(
    `
    update users 
    set 
    is_logged_in = true
    where user_id = $1
    `,
    [userId]
  );
};
export const updateUserLoggedOut = async (userId) => {
  return await pool.query(
    `
    update users 
    set 
    is_logged_in = false
    where user_id = $1
    `,
    [userId]
  );
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
    path: "/auth/verify/email/confirm",
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
    isEmailValid: user.is_email_valid,
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

export const decodeToken = (res, token) => {
  if (!token) return sendError(res, 400, "invalid token expire");
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
      isEmailValid: user.is_email_valid,
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

export const getPassword = async (userId) => {
  const { rows } = await pool.query(
    `
    select * from users
    where user_id = $1
    `,
    [userId]
  );
  return rows[0];
};

export const generateTokenForPass = (userId) => {
  return jwt.sign({ id: userId }, secretKey, { expiresIn: 10 * 60 });
};

export const jwtTokenForPass = async (res, userId) => {
  const tokenForPass = generateTokenForPass(userId);
  console.log(tokenForPass);
  res.cookie("passChange", tokenForPass, {
    httpOnly: true,
    secure: false,
    maxAge: 10 * 60 * 1000,
  });
};
