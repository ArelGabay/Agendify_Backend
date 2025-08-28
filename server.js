const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const tokenStore = require("./controllers/tokenStore");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const cron = require("node-cron");
const { exec } = require("child_process");

process.env.TZ = "Asia/Jerusalem";

cron.schedule("30 13,20 * * *", () => {
  console.log("🕒 Running engagement update script (13:30 or 20:00)");
  exec("node ./scripts/update_engagement_metrics.js", (err, stdout) => {
    if (err) console.error("❌ Script error:", err.message);
    else console.log(stdout);
  });
});

const app = express();
const port = process.env.PORT || 3000;

// trust proxy (needed for correct HTTPS cookie behavior behind Railway)
app.set("trust proxy", 1);

// ---------- Parsers ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- Health checks (keep these BEFORE any async work) ----------
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/healthz", (req, res) => res.status(200).json({ ok: true }));

const allowed = ["http://localhost:5173", "https://agendifyx.up.railway.app"];
const corsMiddleware = cors({
  origin: (origin, cb) => (!origin || allowed.includes(origin) ? cb(null, true) : cb(new Error("CORS blocked"))),
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials: true,
});

app.use(corsMiddleware);
app.options("*", corsMiddleware);              // <- critical so OPTIONS never 405s
app.options("/api/*", corsMiddleware, (req, res) => res.sendStatus(204));

// ---------- Session ----------
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "4971gK2em1SDQllBSio0RJ7Rpjes472QEyZS8wkakrhSMSCKJrMX5MGft9U6giFd",
    resave: false,
    saveUninitialized: true,
    cookie: {
      // Keep your current settings (work in both http local & https prod)
      secure: false,
      sameSite: "lax",
    },
  })
);

// (optional) request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

app.use((req, res, next) => {
  console.log('MAIN:', req.method, req.url);
  next();
});

// ---------- Routes ----------
const authRouter = require("./routes/authRoute");
const twitterRouter = require("./routes/twitter");
const agendasRouter = require("./routes/agendas");
const { router: uploadRouter } = require("./routes/uploadRoute");
const agendaInstance = require("./agenda/agendaInstance");
const loadJobs = require("./agenda/loadJobs");

// ---------- Init ----------
const initApp = async () => {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set");
  }

  try {
    // Remove deprecated flags
    await mongoose.connect(process.env.DATABASE_URL);
    console.log("✅ Connected to Database");

    app.use("/uploads", express.static(path.join(__dirname, "./uploads")));

    app.use("/api/auth", authRouter);
    app.use("/api/twitter", twitterRouter);
    app.use("/api/uploads", uploadRouter);
    app.use("/api/agendas", agendasRouter);

    // ---- OAuth2 PKCE helpers
    const querystring = require("querystring");
    function generateCodeVerifier() {
      return crypto.randomBytes(32).toString("hex");
    }
    function generateCodeChallenge(v) {
      return crypto
        .createHash("sha256")
        .update(v)
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    }

    // 1) Kick off OAuth2 login
    app.get("/auth/twitter", (req, res) => {
      const state = crypto.randomBytes(8).toString("hex");
      const verifier = generateCodeVerifier();
      req.session.codeVerifier = verifier;
      req.session.state = state;
      const challenge = generateCodeChallenge(verifier);
      const params = {
        response_type: "code",
        client_id: process.env.CLIENT_ID,
        redirect_uri: "https://agendifyx.up.railway.app/api/auth/twitter/callback2",
        scope: "tweet.read tweet.write users.read",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      };
      const url =
        "https://twitter.com/i/oauth2/authorize?" +
        querystring.stringify(params);
      res.redirect(url);
    });

    // 2) OAuth2 callback — exchange code for tokens
    app.get("/api/auth/twitter/callback2", async (req, res) => {
      const { code, state } = req.query;
      if (!code || state !== req.session.state || !req.session.codeVerifier) {
        return res.status(400).send("Invalid OAuth callback.");
      }
      const verifier = req.session.codeVerifier;
      req.session.state = null;
      req.session.codeVerifier = null;

      try {
        const resp = await axios.post(
          "https://api.twitter.com/2/oauth2/token",
          querystring.stringify({
            grant_type: "authorization_code",
            code,
            client_id: process.env.CLIENT_ID,
            redirect_uri: "https://agendifyx.up.railway.app/api/auth/twitter/callback2",
            code_verifier: verifier,
          }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization:
                "Basic " +
                Buffer.from(
                  `${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`
                ).toString("base64"),
            },
          }
        );

        const { access_token, refresh_token } = resp.data;
        tokenStore.setUserTokens({
          accessToken: access_token,
          refreshToken: refresh_token,
        });

        res.send(
          `<h1>Twitter Connected!</h1><p>You can now close this window and start promoting.</p>`
        );
      } catch (e) {
        console.error("Error exchanging token:", e.response?.data || e);
        res.status(500).send("OAuth token exchange failed.");
      }
    });

    loadJobs(agendaInstance);
    await agendaInstance.start();
    console.log("🕐 Agenda started");

    return app;
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    throw err;
  }
};

module.exports = initApp;
