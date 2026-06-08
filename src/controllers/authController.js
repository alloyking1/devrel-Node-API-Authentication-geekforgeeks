const bcrypt = require("bcryptjs");
const User = require("../models/User");

const QRCode = require("qrcode");
const { generateSecret, generateURI, verify } = require("otplib");

const Session = require("../models/Session");
const {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  generateMFAToken,
} = require("../utils/tokenUtils");

const jwt = require("jsonwebtoken");

const getRefreshTokenExpiryMs = () => {
  const refreshDays = Number(
    process.env.REFRESH_TOKEN_EXPIRES_DAYS
  );

  return refreshDays * 24 * 60 * 60 * 1000;
};

const getRefreshTokenCookieOptions = () => {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/api/auth",
    maxAge: getRefreshTokenExpiryMs(),
  };
};

const setRefreshTokenCookie = (res, refreshToken) => {
  res.cookie(
    "refreshToken",
    refreshToken,
    getRefreshTokenCookieOptions()
  );
};

const clearRefreshTokenCookie = (res) => {
  res.clearCookie("refreshToken", {
    ...getRefreshTokenCookieOptions(),
    maxAge: undefined,
  });
};

const register = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // Password length check
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters",
      });
    }

    // Check existing user
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists",
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create user
    const user = await User.create({
      email,
      passwordHash,
    });

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: user._id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

const login = async (req, res) => {
    try {
      const { email, password } = req.body;
  
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: "Email and password are required",
        });
      }
  
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }
  
      const isPasswordValid = await bcrypt.compare(
        password,
        user.passwordHash
      );
  
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }
  
      // MFA ENABLED
      if (user.mfaEnabled) {
        const mfaToken = generateMFAToken(user);
  
        return res.status(200).json({
          success: true,
          requiresMFA: true,
          message: "MFA verification required",
          mfaToken,
        });
      }
  
      // MFA DISABLED
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken();
      const refreshTokenHash = hashToken(refreshToken);
      const expiresAt = new Date();
  
      expiresAt.setDate(
        expiresAt.getDate() +
          Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS)
      );
  
      await Session.create({
        userId: user._id,
        refreshTokenHash,
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
        expiresAt,
      });

      setRefreshTokenCookie(res, refreshToken);
  
      return res.status(200).json({
        success: true,
        message: "Login successful",
        accessToken,
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  };

  const setupMFA = async (req, res) => {
    try {
      const user = req.user;
  
      // Generate secret
      const secret = generateSecret();
  
      // Create OTP auth URL
      const otpAuthUrl = generateURI({
        label: user.email,
        issuer: "AdvancedAuthAPI",
        secret,
      });
  
      // Generate QR code
      const qrCodeImageUrl = await QRCode.toDataURL(otpAuthUrl);
  
      // Save secret temporarily
      user.mfaSecret = secret;
  
      await user.save();
  
      return res.status(200).json({
        success: true,
        message: "MFA setup initialized",
        secret,
        qrCodeImageUrl,
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Failed to setup MFA",
      });
    }
  };

  const verifyMFA = async (req, res) => {
    try {
      const user = req.user;
  
      const { token } = req.body;
  
      if (!token) {
        return res.status(400).json({
          success: false,
          message: "MFA token is required",
        });
      }
  
      const verification = await verify({
        token,
        secret: user.mfaSecret,
      });

      const isValid = verification?.valid === true;
  
      if (!isValid) {
        return res.status(401).json({
          success: false,
          message: "Invalid MFA code",
        });
      }
  
      user.mfaEnabled = true;
  
      await user.save();
  
      return res.status(200).json({
        success: true,
        message: "MFA enabled successfully",
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Failed to verify MFA",
      });
    }
  };

  const verifyMFALogin = async (req, res) => {
    try {
      const { token, mfaToken } = req.body;
  
      if (!token || !mfaToken) {
        return res.status(400).json({
          success: false,
          message: "Token and MFA token are required",
        });
      }
  
      // Verify temporary MFA JWT
      const decoded = jwt.verify(
        mfaToken,
        process.env.JWT_ACCESS_SECRET
      );
  
      if (decoded.type !== "mfa") {
        return res.status(401).json({
          success: false,
          message: "Invalid MFA session",
        });
      }
  
      const user = await User.findById(decoded.userId);
  
      if (!user || !user.mfaEnabled) {
        return res.status(401).json({
          success: false,
          message: "Invalid user",
        });
      }
  
      // Verify OTP
      const verification = await verify({
        token,
        secret: user.mfaSecret,
      });
  
      const isValid = verification?.valid === true;
  
      if (!isValid) {
        return res.status(401).json({
          success: false,
          message: "Invalid MFA code",
        });
      }
  
      // Issue REAL auth tokens
      const accessToken = generateAccessToken(user);
  
      const refreshToken = generateRefreshToken();
  
      const refreshTokenHash = hashToken(refreshToken);
  
      const expiresAt = new Date();
  
      expiresAt.setDate(
        expiresAt.getDate() +
          Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS)
      );
  
      await Session.create({
        userId: user._id,
        refreshTokenHash,
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
        expiresAt,
      });

      setRefreshTokenCookie(res, refreshToken);
  
      return res.status(200).json({
        success: true,
        message: "MFA login successful",
        accessToken,
      });
    } catch (error) {
      console.error(error);
  
      return res.status(401).json({
        success: false,
        message: "Invalid or expired MFA session",
      });
    }
  };

  const getMe = async (req, res) => {
    return res.status(200).json({
      success: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        mfaEnabled: req.user.mfaEnabled,
      },
    });
  };


  const refreshAccessToken = async (req, res) => {
    try {
      const refreshToken = req.cookies?.refreshToken;
  
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: "Refresh token cookie required",
        });
      }
  
      const refreshTokenHash = hashToken(refreshToken);
  
      const session = await Session.findOne({
        refreshTokenHash,
        revokedAt: null,
      });
  
      if (!session) {
        clearRefreshTokenCookie(res);

        return res.status(401).json({
          success: false,
          message: "Invalid session",
        });
      }
  
      // Expired session
      if (session.expiresAt < new Date()) {
        clearRefreshTokenCookie(res);

        return res.status(401).json({
          success: false,
          message: "Session expired",
        });
      }
  
      const user = await User.findById(session.userId);
  
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid user",
        });
      }
  
      // ROTATE REFRESH TOKEN
      const newRefreshToken = generateRefreshToken();
  
      const newRefreshTokenHash = hashToken(newRefreshToken);
  
      session.refreshTokenHash = newRefreshTokenHash;
  
      await session.save();

      setRefreshTokenCookie(res, newRefreshToken);
  
      // Generate new access token
      const accessToken = generateAccessToken(user);
  
      return res.status(200).json({
        success: true,
        accessToken,
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Failed to refresh token",
      });
    }
  };

  const logout = async (req, res) => {
    try {
      const refreshToken = req.cookies?.refreshToken;
  
      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: "Refresh token cookie required",
        });
      }
  
      const refreshTokenHash = hashToken(refreshToken);
  
      await Session.findOneAndUpdate(
        {
          refreshTokenHash,
          revokedAt: null,
        },
        {
          revokedAt: new Date(),
        }
      );

      clearRefreshTokenCookie(res);
  
      return res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Logout failed",
      });
    }
  };

  const logoutAll = async (req, res) => {
    try {
      await Session.updateMany(
        {
          userId: req.user._id,
          revokedAt: null,
        },
        {
          revokedAt: new Date(),
        }
      );

      clearRefreshTokenCookie(res);
  
      return res.status(200).json({
        success: true,
        message: "Logged out from all devices",
      });
    } catch (error) {
      console.error(error);
  
      return res.status(500).json({
        success: false,
        message: "Failed to logout all sessions",
      });
    }
  };

  module.exports = {
    register,
    login,
    setupMFA,
    verifyMFA,
    verifyMFALogin,
    getMe,
    refreshAccessToken,
    logout,
    logoutAll,
  };