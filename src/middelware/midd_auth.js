import { decodeToken, refreshTokens } from "../services/user.service.js";
export const authorization = async (req, res, next) => {
  try {
    const { accessToken, refreshToken } = req.cookies;
    if (!accessToken && !refreshToken) {
      req.user = null;
      return next();
    }

    if (accessToken) {
      const data = decodeToken(res, accessToken);
      req.user = data;
      return next();
    }

    if (refreshToken) {
      try {
        const { newAccessToken, newRefreshToken, user } = await refreshTokens(
          refreshToken
        );
        res.cookie("accessToken", newAccessToken, {
          httpOnly: false,
          secure: false,
          maxAge: 15 * 60 * 1000,
        });
        res.cookie("refreshToken", newRefreshToken, {
          httpOnly: false,
          secure: false,
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        req.user = user;
        return next();
      } catch (error) {
        req.user = null;
        return next();
      }
    }
    return next();
  } catch (error) {
    req.user = null;
    return next(error);
  }
};
