"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));
app.use(cors());

const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const APP_NAME = "NX USDT";
const ADSGRAM_BLOCK_ID = "52783";

const JOINING_BONUS_USDT = Number(
  process.env.JOINING_BONUS_USDT || "10"
);

const REFERRAL_REWARD_USDT = Number(
  process.env.REFERRAL_REWARD_USDT || "5"
);

const AD_REWARD_USDT = Number(
  process.env.AD_REWARD_USDT || "0.0005"
);

const MIN_WITHDRAWAL_USDT = Number(
  process.env.MIN_WITHDRAWAL_USDT || "5"
);

const REQUIRED_ADS = 5;
const REQUIRED_TASKS = 4;

if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    "Missing BOT_TOKEN, SUPABASE_URL, or SUPABASE_SERVICE_ROLE_KEY."
  );
  process.exit(1);
}

for (const [name, value] of Object.entries({
  JOINING_BONUS_USDT,
  REFERRAL_REWARD_USDT,
  AD_REWARD_USDT,
  MIN_WITHDRAWAL_USDT,
})) {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be non-negative.`);
  }
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  }
);

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message,
  });
}

function roundUSDT(value) {
  return Math.round((Number(value) + Number.EPSILON) * 1e8) / 1e8;
}

function validTelegramId(value) {
  return /^\d{1,20}$/.test(String(value || ""));
}

function getTelegramInitData(req) {
  const value =
    req.body?.initData ||
    req.body?.telegramInitData ||
    req.headers["x-telegram-init-data"];

  return typeof value === "string" ? value : "";
}

// =============================================
// VERIFY TELEGRAM MINI APP USER
// =============================================

function verifyTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    throw new Error("Telegram authentication data is missing.");
  }

  if (initData.length > 16000) {
    throw new Error("Telegram authentication data is too large.");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    throw new Error("Invalid Telegram authentication hash.");
  }

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isFinite(authDate) ||
    authDate > now + 60 ||
    now - authDate > 3600
  ) {
    throw new Error("Telegram session expired. Reopen NX USDT.");
  }

  const entries = [];

  for (const [key, value] of params.entries()) {
    if (key !== "hash") entries.push([key, value]);
  }

  entries.sort(([a], [b]) => a.localeCompare(b));

  const dataCheckString = entries
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const actual = Buffer.from(receivedHash, "hex");
  const expected = Buffer.from(calculatedHash, "hex");

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    throw new Error("Telegram authentication failed.");
  }

  let user;

  try {
    user = JSON.parse(params.get("user") || "null");
  } catch {
    throw new Error("Invalid Telegram user data.");
  }

  if (!user || !validTelegramId(user.id)) {
    throw new Error("Telegram user ID is invalid.");
  }

  return {
    id: String(user.id),
    first_name: String(user.first_name || "").slice(0, 100),
    username: String(user.username || "").slice(0, 100),
    photo_url: String(user.photo_url || "").slice(0, 1000),
    start_param: String(params.get("start_param") || "").slice(0, 150),
  };
}

function requireUser(req, res, next) {
  try {
    req.telegramUser = verifyTelegramInitData(
      getTelegramInitData(req)
    );
    next();
  } catch (error) {
    return sendError(res, 401, error.message);
  }
}

// =============================================
// DATABASE HELPERS
// =============================================

async function getUser(telegramId) {
  const { data, error } = await supabase
    .from("trial_users")
    .select("*")
    .eq("telegram_id", telegramId)
    .maybeSingle();

  if (error) throw error;

  return data;
}

async function getUserStats(telegramId) {
  const [ads, tasks, referrals, payouts] = await Promise.all([
    supabase
      .from("trial_ad_claims")
      .select("id", { count: "exact", head: true })
      .eq("telegram_id", telegramId),

    supabase
      .from("trial_task_claims")
      .select("id", { count: "exact", head: true })
      .eq("telegram_id", telegramId),

    supabase
      .from("trial_users")
      .select("telegram_id", { count: "exact", head: true })
      .eq("referred_by", telegramId),

    supabase
      .from("trial_payouts")
      .select("*")
      .eq("telegram_id", telegramId)
      .order("created_at", { ascending: false })
      .limit(50),
  ]);

  for (const result of [ads, tasks, referrals, payouts]) {
    if (result.error) throw result.error;
  }

  return {
    adsWatched: ads.count || 0,
    tasksCompleted: tasks.count || 0,
    referralsCount: referrals.count || 0,
    payouts: payouts.data || [],
  };
}

async function buildUserResponse(telegramUser) {
  const user = await getUser(telegramUser.id);

  if (!user) {
    throw new Error("Account not initialized. Call /sync first.");
  }

  const stats = await getUserStats(telegramUser.id);

  return {
    user: {
      id: user.telegram_id,
      first_name: user.first_name,
      username: user.username,
    },

    balance: Number(user.balance_usdt || 0),
    referrals: stats.referralsCount,
    referralReward: REFERRAL_REWARD_USDT,

    referralLink:
      `https://t.me/NXCoinRobot/Web?startapp=ref_${user.telegram_id}`,

    referralHistory: [],
    adsWatched: stats.adsWatched,
    tasksCompleted: stats.tasksCompleted,

    requiredAds: REQUIRED_ADS,
    requiredTasks: REQUIRED_TASKS,

    canWithdraw:
      stats.adsWatched >= REQUIRED_ADS &&
      stats.tasksCompleted >= REQUIRED_TASKS &&
      Number(user.balance_usdt || 0) >= MIN_WITHDRAWAL_USDT,

    payouts: stats.payouts,

    config: {
      appName: APP_NAME,
      joiningBonusUSDT: JOINING_BONUS_USDT,
      referralRewardUSDT: REFERRAL_REWARD_USDT,
      adRewardUSDT: AD_REWARD_USDT,
      minWithdrawalUSDT: MIN_WITHDRAWAL_USDT,
      requiredAds: REQUIRED_ADS,
      requiredTasks: REQUIRED_TASKS,
      adsgramBlockId: ADSGRAM_BLOCK_ID,
    },
  };
}

// =============================================
// HEALTH CHECK
// =============================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    app: APP_NAME,
    status: "online",
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
  });
});

// =============================================
// SYNC USER AND REGISTER REFERRAL
// =============================================

app.post("/sync", requireUser, async (req, res) => {
  try {
    const user = req.telegramUser;

    const startParam = String(
      req.body?.startParam || user.start_param || ""
    );

    let referrerId = null;

    if (/^ref_\d{1,20}$/.test(startParam)) {
      referrerId = startParam.slice(4);

      if (referrerId === user.id) {
        referrerId = null;
      }
    }

    const { error } = await supabase.rpc("trial_sync_user", {
      p_telegram_id: user.id,
      p_first_name: user.first_name,
      p_username: user.username || null,
      p_photo_url: user.photo_url || null,
      p_referrer_id: referrerId,
      p_joining_bonus: JOINING_BONUS_USDT,
      p_referral_reward: REFERRAL_REWARD_USDT,
    });

    if (error) {
      console.error("/sync database error:", error.message);
      return sendError(res, 500, "Account initialization failed.");
    }

    const response = await buildUserResponse(user);

    return res.json({
      success: true,
      ...response,
    });
  } catch (error) {
    console.error("/sync:", error.message);
    return sendError(res, 500, "Could not load account.");
  }
});

// =============================================
// ACCOUNT REFRESH
// =============================================

app.post("/account", requireUser, async (req, res) => {
  try {
    const response = await buildUserResponse(req.telegramUser);

    return res.json({
      success: true,
      ...response,
    });
  } catch (error) {
    console.error("/account:", error.message);
    return sendError(res, 500, "Could not load account.");
  }
});

// =============================================
// ADSGRAM CLAIM
// =============================================

app.post("/adsgram/claim", requireUser, async (req, res) => {
  try {
    const adId = String(req.body?.adId || req.body?.ad_id || "");

    if (!/^(101|102|103|104|105)$/.test(adId)) {
      return sendError(res, 400, "Invalid ad ID.");
    }

    const { data, error } = await supabase.rpc("trial_claim_ad", {
      p_telegram_id: req.telegramUser.id,
      p_ad_id: adId,
      p_reward: AD_REWARD_USDT,
    });

    if (error) {
      console.error("/adsgram/claim:", error.message);
      return sendError(res, 400, "Ad claim failed.");
    }

    return res.json({
      success: true,
      reward: AD_REWARD_USDT,
      result: data,
    });
  } catch (error) {
    console.error("/adsgram/claim:", error.message);
    return sendError(res, 500, "Could not process ad reward.");
  }
});

// =============================================
// SOCIAL TASK CLAIM
// =============================================

app.post("/earn", requireUser, async (req, res) => {
  try {
    const taskId = Number(req.body?.taskId ?? req.body?.task_id);

    if (!Number.isInteger(taskId) || taskId < 1 || taskId > 4) {
      return sendError(res, 400, "Invalid task ID.");
    }

    const { data, error } = await supabase.rpc("trial_claim_task", {
      p_telegram_id: req.telegramUser.id,
      p_task_id: taskId,
    });

    if (error) {
      console.error("/earn:", error.message);
      return sendError(res, 400, "Task claim failed.");
    }

    return res.json({
      success: true,
      result: data,
    });
  } catch (error) {
    console.error("/earn:", error.message);
    return sendError(res, 500, "Could not process task.");
  }
});

// =============================================
// WITHDRAWAL REQUEST
// =============================================

app.post("/payout", requireUser, async (req, res) => {
  try {
    const amount = Number(req.body?.amount);

    const walletAddress = String(
      req.body?.walletAddress ||
      req.body?.wallet_address ||
      ""
    ).trim();

    if (
      !Number.isFinite(amount) ||
      amount < MIN_WITHDRAWAL_USDT ||
      amount > 100000000
    ) {
      return sendError(
        res,
        400,
        `Minimum withdrawal is ${MIN_WITHDRAWAL_USDT} USDT.`
      );
    }

    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      return sendError(res, 400, "Enter a valid EVM wallet address.");
    }

    const { data, error } = await supabase.rpc(
      "trial_request_payout",
      {
        p_telegram_id: req.telegramUser.id,
        p_amount: roundUSDT(amount),
        p_wallet_address: walletAddress,
        p_minimum: MIN_WITHDRAWAL_USDT,
        p_required_ads: REQUIRED_ADS,
        p_required_tasks: REQUIRED_TASKS,
      }
    );

    if (error) {
      console.error("/payout:", error.message);
      return sendError(
        res,
        400,
        "Withdrawal request failed. Check your balance and eligibility."
      );
    }

    return res.json({
      success: true,
      result: data,
      message: "Withdrawal request submitted for review.",
    });
  } catch (error) {
    console.error("/payout:", error.message);
    return sendError(res, 500, "Could not submit withdrawal request.");
  }
});

// =============================================
// PAYOUT HISTORY
// =============================================

app.post("/payouts", requireUser, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("trial_payouts")
      .select("*")
      .eq("telegram_id", req.telegramUser.id)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) throw error;

    return res.json({
      success: true,
      payouts: data || [],
    });
  } catch (error) {
    console.error("/payouts:", error.message);
    return sendError(res, 500, "Could not load payout history.");
  }
});

// =============================================
// ADMIN PAYOUT STATUS
// =============================================

function requireAdmin(req, res, next) {
  const adminSecret = process.env.ADMIN_SECRET;

  if (!adminSecret) {
    return sendError(res, 503, "Admin controls are disabled.");
  }

  const supplied = String(req.headers["x-admin-secret"] || "");

  const a = Buffer.from(supplied);
  const b = Buffer.from(adminSecret);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return sendError(res, 401, "Unauthorized.");
  }

  next();
}

app.post("/admin/payout", requireAdmin, async (req, res) => {
  try {
    const payoutId = String(req.body?.payoutId || "");
    const status = String(req.body?.status || "");

    if (!/^[0-9a-f-]{36}$/i.test(payoutId)) {
      return sendError(res, 400, "Invalid payout ID.");
    }

    if (!["approved", "rejected", "paid"].includes(status)) {
      return sendError(res, 400, "Invalid payout status.");
    }

    const { data, error } = await supabase
      .from("trial_payouts")
      .update({
        status,
        updated_at: new Date().toISOString(),
      })
      .eq("id", payoutId)
      .select()
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return sendError(res, 404, "Payout not found.");
    }

    return res.json({
      success: true,
      payout: data,
    });
  } catch (error) {
    console.error("/admin/payout:", error.message);
    return sendError(res, 500, "Could not update payout.");
  }
});

// =============================================
// UNKNOWN ROUTE
// =============================================

app.use((req, res) => {
  return sendError(res, 404, "API endpoint not found.");
});

// =============================================
// START SERVER
// =============================================

app.listen(PORT, () => {
  console.log(`${APP_NAME} API running on port ${PORT}`);
  console.log(`AdsGram Block ID: ${ADSGRAM_BLOCK_ID}`);
});
