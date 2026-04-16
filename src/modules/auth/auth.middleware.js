import ApiError from "../../common/utiles/api-error.js";
import { verifyAccessToken } from "../../common/utiles/jwt.utils.js";

import { pool } from "../../../index.js";
// Authenticates using the short-lived access token (header or cookie)
const authenticate = async (req, res, next) => {
    let token;
    if (req.headers.authorization?.startsWith("Bearer")) {
      token = req.headers.authorization.split(" ")[1];
    }
    
  if (!token) throw ApiError.unauthorized("Not authenticated");

  const decoded = verifyAccessToken(token);
  const sql = "SELECT * FROM users WHERE user_id=$1"
  const user = await pool.query(sql,[decoded.id])
  if (user.rowCount===0) throw ApiError.unauthorized("User no longer exists");
  const dbuser = user.rows[0]

  req.user = {
    id: dbuser.user_id,
    role: dbuser.role,
    name: dbuser.name,
    email:dbuser.email,
  };
next();

};

// Higher-order function — returns middleware configured with allowed roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw ApiError.forbidden(
        "You do not have permission to perform this action",
      );
    }
    next();
  };
};

export { authenticate, authorize };