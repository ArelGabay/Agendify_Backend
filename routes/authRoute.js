const express = require("express");
const authController = require("../controllers/authController");
const { upload } = require("./uploadRoute");

const router = express.Router();

router.use((req, res, next) => {
  console.log('ROUTER:', req.method, req.path);
  next();
});

// Register user (with optional profile picture)
router.post("/register", upload.single("profilePicture"), authController.register);

// Google sign-in
router.post("/google", authController.googleSignin);

// Login user with username & password
router.post("/login", authController.login);

// Refresh token
router.post("/refresh", authController.refresh);

// Logout user (invalidate refresh token)
router.post("/logout", authController.logout);

module.exports = router;
