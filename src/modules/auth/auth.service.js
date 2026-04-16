import crypto from "crypto";
// import User from "./auth.model.js";
import ApiError from "../../common/utiles/api-error.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateResetToken,
} from "../../common/utiles/jwt.utils.js";
// import {
//   sendVerificationEmail,
//   sendResetPasswordEmail,
// } from "../../common/config/email.js";
import { pool } from "../../../index.js";
import bcrypt from "bcryptjs";
// import { Result } from "pg";
// import { waitForDebugger } from "inspector";
// import pool from "index.js"



// Hash refresh token before storing — same approach as reset tokens
const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

const register = async ({ name, email, password, role }) => {
  const sql = "SELECT * FROM users where email=$1";

  const existing = await pool.query(sql,[email]);
  if (existing.rowCount>0) throw ApiError.conflict("Email already registered");
  const hashedPassword = await bcrypt.hash(password, 10);

  const { rawToken, hashedToken } = generateResetToken();
  const sqlU = "INSERT INTO users (name,email,password,role,verification_token) VALUES ($1,$2,$3,$4,$5) RETURNING *";
  const user = await pool.query(sqlU,[name,email,hashedPassword,role,hashedToken])

  // const user = await User.create({
  //   name,
  //   email,
  //   password,
  //   role,
  //   verificationToken: hashedToken,
  // });

  // Don't let email failure crash registration — user is already created
  // try {
  //   await sendVerificationEmail(email, rawToken);
  // } catch (err) {
  //   console.error("Failed to send verification email:", err.message);
  // }

  const userObj = user.rows[0];
  delete userObj.password;
  delete userObj.verification_token;

  return userObj;
};

const login = async ({ email, password }) => {
  const sql = "SELECT * FROM users WHERE email=$1";
const user = await pool.query(sql,[email]);
  // const user = await User.findOne({ email }).select("+password");
  if (user.rowCount===0) throw ApiError.unauthorized("Invalid email or password");

  const dbUser = user.rows[0];
  const isMatch = await bcrypt.compare(password, dbUser.password);

  // const isMatch = await user.comparePassword(password);
  if (!isMatch) throw ApiError.unauthorized("Invalid email or password");

  if (!dbUser.is_verified) {
    throw ApiError.forbidden("Please verify your email before logging in");
  }

  const accessToken = generateAccessToken({ id: dbUser.user_id, role: dbUser.role});
  const refreshToken = generateRefreshToken({ id: dbUser.user_id });

  // Store hashed refresh token in DB so it can be invalidated on logout
  const sqlU = "UPDATE users SET refresh_token=$1 WHERE email=$2";
  const refreshTokens = hashToken(refreshToken);
  await pool.query(sqlU,[refreshTokens,dbUser.email])
  // await user.save({ validateBeforeSave: false });

  const userObj = user.rows[0];
  delete userObj.password;
  delete userObj.refresh_token;

  return { user: userObj, accessToken, refreshToken };
};

// Issues a new access token using a valid refresh token
const refresh = async (token) => {
  if (!token) throw ApiError.unauthorized("Refresh token missing");

  const decoded = verifyRefreshToken(token);
const sql = "SELECT * FROM users where user_id=$1";
const user = await pool.query(sql,[decoded.id]);
const result = user.rows[0];
  // const user = await User.findById(decoded.id).select("+refreshToken");
  if (user.rowCount===0) throw ApiError.unauthorized("User no longer exists");

  // Verify the refresh token matches what's stored (prevents reuse of old tokens)
  if (result.refresh_token !== hashToken(token)) {
    throw ApiError.unauthorized("Invalid refresh token — please log in again");
  }

  const accessToken = generateAccessToken({ id:result.user_id, role: result.role });

  return { accessToken };
};

const logout = async (userId) => {
  const sql = "UPDATE users SET refresh_token=$1 where user_id=$2";
  await pool.query(sql,[null,userId])
  // Clear stored refresh token so it can't be reused
  // await User.findByIdAndUpdate(userId, { refreshToken: null });
};

const verifyEmail = async (token) => {
  const trimmed = String(token).trim();
  if (!trimmed) {
    throw ApiError.badRequest("Invalid or expired verification token");
  }

  // DB stores SHA256(raw). Links / email use the raw token — we hash for lookup.
  // If you paste the hash from MongoDB into Postman, hashing again would not match;
  // so we also try a direct match on the stored VALUES.
  const hashedInput = hashToken(trimmed);
  const sql = "SELECT * FROM users where verification_token=$1";
  const user = await pool.query(sql,[hashedInput]);
  // let user = await User.findOne({ verificationToken: hashedInput }).select(
  //   "+verificationToken",
  // );
  // if (!user) {
  //   user = await User.findOne({ verificationToken: trimmed }).select(
  //     "+verificationToken",
  //   );
  // }
  if (user.rowCount===0) throw ApiError.badRequest("Invalid or expired verification token");
  const dbuser= user.rows[0]
const sqlU = "UPDATE users SET is_verified=$1,verification_token=$2 where user_id=$3";
await pool.query(sqlU,[true,null,dbuser.user_id]);
  // await User.findByIdAndUpdate(user.user_id, {
  //   $set: { isVerified: true },
  //   $unset: { verificationToken: 1 },
  // });

  return dbuser;
};

const forgotPassword = async (email) => {
    const sql = "SELECT * FROM users where email=$1";
const user = await pool.query(sql,[email]);
  // const user = await User.findOne({ email });
  if (user.rowCount===0) throw ApiError.notFound("No account with that email");

  const { rawToken, hashedToken } = generateResetToken();
const sqlU = "UPDATE users SET reset_password_token=$1,reset_password_expires=$2 where email=$3";
await pool.query(sqlU,[hashedToken,Date.now() +15*60*1000,email]);
  // user.resetPasswordToken = hashedToken;
  // user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;
  // await user.save();

  // try {
  //   await sendResetPasswordEmail(email, rawToken);
  // } catch (err) {
  //   console.error("Failed to send reset email:", err.message);
  // }
};

const resetPassword = async (token, newPassword) => {
  const hashedToken = hashToken(token);
  const sql = "SELECT * FROM users where reset_password_token=$1 AND reset_password_expires>$2";
  const user = await pool.query(sql,[hashedToken,Date.now()]);

  // const user = await User.findOne({
  //   resetPasswordToken: hashedToken,
  //   resetPasswordExpires: { $gt: Date.now() },
  // }).select("+resetPasswordToken +resetPasswordExpires");
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  if (user.rowCount===0) throw ApiError.badRequest("Invalid or expired reset token");
const sqlU = "UPDATE users SET password=$1, reset_password_token=$2,reset_password_expires=$3 where reset_password_token=$4 AND reset_password_expires>$5";
await pool.query(sqlU,[hashedPassword,null,null,hashedToken,Date.now()]);
  // user.password = newPassword;
  // user.resetPasswordToken = undefined;
  // user.resetPasswordExpires = undefined;
  // await user.save();
};

const getMe = async (userId) => {
  const sql = "SELECT * FROM users where user_id=$1";
  const user = await pool.query(sql,[userId]);
  // const user = await User.findById(userId);
  if (user.rowCount===0) throw ApiError.notFound("User not found");
  return user.rows[0];
};



export {
  register,
  login,
  refresh,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getMe,

};