import express from "express";
import { login, logout, register, verifyEmail, sendVerifyOtp, isAuthenticated, resentOTP,resetPassword } from "../controllers/authControllers.js";
import userAuth from "../middleware/userAuth.js";


const authRoutes = express.Router();

authRoutes.post("/register", register)
authRoutes.post("/login", login)
authRoutes.post("/logout", logout)
authRoutes.post("/send-verify-otp", userAuth, sendVerifyOtp)
authRoutes.post("/verify-account", userAuth, verifyEmail)
authRoutes.post("/is-authenticated", isAuthenticated)
authRoutes.post("/reset-otp", userAuth, resentOTP)
authRoutes.post("/reset-password", userAuth, resetPassword)



export default authRoutes;