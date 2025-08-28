// src/models/Bot.js
const mongoose = require("mongoose");

const botSchema = new mongoose.Schema(
  {
    botId: { type: String, required: true, unique: true },
    apiKey: { type: String, required: true },
    apiSecret: { type: String, required: true },
    bearerToken: { type: String, required: true },
    accessToken: { type: String, required: true },
    accessTokenSecret: { type: String, required: true },
    clientId: { type: String, required: true },
    clientSecret: { type: String, required: true },
    lastUsedAt: { type: Date, default: null },
    role: {
      type: String,
      enum: ["all", "fetch", "reply", "track"],
      default: "all",
    },
    monthlyReset: { type: Date, default: null }, // seeded from CSV
    nextFetchReset: { type: Date, default: null }, // runtime lock
    nextReplyReset: { type: Date, default: null }, // runtime lock
    plan: { type: String, requied: true },

    // ← new fields:
    fetchCount: { type: Number, default: 0 },
    replyCount: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Bot", botSchema);
