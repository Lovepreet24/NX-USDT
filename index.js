'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const WebSocket = require('ws');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers'); // ethers v6

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

const PORT = Number(process.env.PORT || 8080);

const BOT_TOKEN = process.env.BOT_TOKEN;
const BOT_USERNAME = String(process.env.BOT_USERNAME || 'NXCoinRobot').replace(/^@/, '');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const JOINING_BONUS = Number(process.env.JOINING_BONUS_USDT || 10);
const REFERRAL_REWARD = Number(process.env.REFERRAL_REWARD_USDT || 5);
const TASK_REWARD = Number(process.env.TASK_REWARD_USDT || 0.25);
const AD_REWARD = Number(process.env.AD_REWARD_USDT || 0.25);
const MIN_WITHDRAWAL = Number(process.env.MIN_WITHDRAWAL_USDT || 5);
const MAX_WITHDRAWAL = Number(process.env.MAX_WITHDRAWAL_USDT || 100);
const REQUIRED_ADS = Number(process.env.REQUIRED_ADS_TO_WITHDRAW || 5);
const REQUIRED_TASKS = Number(process.env.REQUIRED_SOCIAL_TASKS_TO_WITHDRAW || 2);
const ADSGRAM_BLOCK_ID = String(process.env.ADSGRAM_BLOCK_ID || '52783');
const ADSGRAM_REWARD_SECRET = process.env.ADSGRAM_REWARD_SECRET || '';

const ADS_PER_24H = 12;
const AD_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const REQUIRE_AD_CLICK = process.env.REQUIRE_AD_CLICK !== 'false';

/* Ad slots where the "Go!" click is NOT required (watching the full ad is enough). */
const NO_CLICK_AD_SLOTS = String(process.env.NO_CLICK_AD_SLOTS || '1')
  .split(',')
  .map(x => Number(x.trim()))
  .filter(n => Number.isInteger(n) && n >= 1);

function adNeedsClick(adId) {
  return REQUIRE_AD_CLICK && !NO_CLICK_AD_SLOTS.includes(adId);
}

/* ---- Auto payout (BEP-20 USDT) ---- */
const AUTO_PAYOUT_ENABLED = process.env.AUTO_PAYOUT_ENABLED === 'true';
const AUTO_PAYOUT_MAX_USDT = Number(process.env.AUTO_PAYOUT_MAX_USDT || 20);
const BSC_RPC_URL = process.env.BSC_RPC_URL || 'https://bsc-dataseed.binance.org/';
const PAYOUT_PRIVATE_KEY = process.env.PAYOUT_PRIVATE_KEY || '';
const USDT_CONTRACT =
  process.env.USDT_CONTRACT || '0x55d398326f99059fF775485246999027B3197955'; // BSC USDT
const USDT_DECIMALS = Number(process.env.USDT_DECIMALS || 18);

/* ---- Tasks ---- */
const AUTO_VERIFY_TASKS = process.env.AUTO_VERIFY_TASKS !== 'false';
const TASKS = {
  telegram_earn: { type: 'telegram', chat: process.env.CHANNEL_EARN || '@NXUSDTEarn' },
  telegram_payout: { type: 'telegram', chat: process.env.CHANNEL_PAYOUT || '@NXUSDTPayout' },
  youtube_1: { type: 'youtube' },
  youtube_2: { type: 'youtube' },
  youtube_3: { type: 'youtube' },
  youtube_4: { type: 'youtube' }
};
const TASK_KEYS = Object.keys(TASKS);

/* YouTube tasks: user must wait this long between START and VERIFY. */
const YOUTUBE_WATCH_SECONDS = Number(process.env.YOUTUBE_WATCH_SECONDS || 35);
/* true = reward right after the timer passes; false = goes to admin review. */
const YOUTUBE_AUTO_APPROVE = process.env.YOUTUBE_AUTO_APPROVE !== 'false';
/* YouTube tasks can be done again this long after the last approval. */
const YOUTUBE_REPEAT_MS = 24 * 60 * 60 * 1000;

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://nxcoinwebbot.vercel.app')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

if (
  !Number.isFinite(AD_REWARD) || AD_REWARD <= 0 ||
  !Number.isFinite(TASK_REWARD) || TASK_REWARD <= 0
) {
  console.error('Invalid reward configuration.');
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
  realtime: { transport: WebSocket }
});

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS.'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-telegram-init-data', 'x-admin-secret']
}));

function fail(res, status, error, extra = {}) {
  return res.status(status).json({ success: false, error, ...extra });
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length > 0 && x.length === y.length && crypto.timingSafeEqual(x, y);
}

function getInitData(req) {
  const value =
    req.body?.initData ||
    req.body?.telegramInitData ||
    req.headers['x-telegram-init-data'];
  return typeof value === 'string' ? value : '';
}

function verifyTelegramInitData(raw) {
  if (!raw || raw.length > 16000) {
    throw new Error('Open NX USDT through Telegram Mini App.');
  }

  const params = new URLSearchParams(raw);
  const hash = params.get('hash');

  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
    throw new Error('Invalid Telegram authentication data.');
  }

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);

  /* 24 hours: users keep the Mini App open for a long time. */
  if (!Number.isFinite(authDate) || authDate > now + 60 || now - authDate > 86400) {
    throw new Error('Telegram session expired. Reopen the Mini App.');
  }

  const pairs = [];
  for (const [key, value] of params.entries()) {
    if (key !== 'hash') pairs.push([key, value]);
  }
  pairs.sort(([a], [b]) => a.localeCompare(b));

  const checkString = pairs.map(([key, value]) => `${key}=${value}`).join('\n');

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calculatedHash = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');

  if (!safeEqual(hash.toLowerCase(), calculatedHash.toLowerCase())) {
    throw new Error('Telegram authentication failed.');
  }

  let user;
  try {
    user = JSON.parse(params.get('user') || 'null');
  } catch {
    throw new Error('Invalid Telegram user data.');
  }

  if (!user || !/^\d{1,20}$/.test(String(user.id))) {
    throw new Error('Telegram user ID is missing.');
  }

  return {
    id: String(user.id),
    first_name: String(user.first_name || '').slice(0, 100),
    username: String(user.username || '').slice(0, 100),
    photo_url: String(user.photo_url || '').slice(0, 1000),
    start_param: String(params.get('start_param') || '').slice(0, 150)
  };
}

function authTelegram(req, res, next) {
  try {
    req.telegramUser = verifyTelegramInitData(getInitData(req));
    next();
  } catch (error) {
    return fail(res, 401, error.message);
  }
}

function authAdmin(req, res, next) {
  if (!ADMIN_SECRET) return fail(res, 503, 'Admin controls are disabled.');
  if (!safeEqual(req.headers['x-admin-secret'], ADMIN_SECRET)) {
    return fail(res, 401, 'Unauthorized admin request.');
  }
  next();
}

async function rpc(name, args) {
  const { data, error } = await db.rpc(name, args);
  if (error) {
    console.error(`RPC ${name}:`, error.message);
    throw error;
  }
  return data;
}

/* Latest verified claim for every ad slot within the rolling 24-hour window. */
async function getAdCooldowns(telegramId) {
  const since = new Date(Date.now() - AD_COOLDOWN_MS).toISOString();

  const { data, error } = await db
    .from('trial_ad_claims')
    .select('ad_id,created_at,reward_usdt,verification_status')
    .eq('telegram_id', telegramId)
    .eq('verification_status', 'verified')
    .gte('created_at', since)
    .order('created_at', { ascending: false });

  if (error) throw error;

  const latestByAd = {};
  const now = Date.now();

  for (const row of data || []) {
    const adId = Number(row.ad_id);

    if (!Number.isInteger(adId) || adId < 1 || adId > ADS_PER_24H || latestByAd[adId]) {
      continue;
    }

    const watchedAt = new Date(row.created_at).getTime();
    if (!Number.isFinite(watchedAt)) continue;

    const availableAt = watchedAt + AD_COOLDOWN_MS;
    const remainingMs = Math.max(0, availableAt - now);

    latestByAd[adId] = {
      adId,
      verified: true,
      locked: remainingMs > 0,
      lastWatchedAt: row.created_at,
      availableAgainAt: new Date(availableAt).toISOString(),
      remainingSeconds: Math.ceil(remainingMs / 1000),
      reward: Number(row.reward_usdt || AD_REWARD)
    };
  }

  const ads = [];
  for (let adId = 1; adId <= ADS_PER_24H; adId++) {
    ads.push(
      latestByAd[adId] || {
        adId,
        verified: false,
        locked: false,
        lastWatchedAt: null,
        availableAgainAt: null,
        remainingSeconds: 0,
        reward: 0
      }
    );
  }

  return ads;
}

/* ---------- YouTube 24h repeat (uses table trial_task_cooldowns) ---------- */
function formatDuration(seconds) {
  const s = Math.max(0, Math.ceil(Number(seconds) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${Math.max(1, m)}m`;
}

/* Remember when a YouTube task was last approved. Never throws. */
async function markTaskDone(userId, taskKey) {
  if (TASKS[taskKey]?.type !== 'youtube') return;

  try {
    const { error } = await db
      .from('trial_task_cooldowns')
      .upsert(
        {
          telegram_id: String(userId),
          task_key: taskKey,
          completed_at: new Date().toISOString()
        },
        { onConflict: 'telegram_id,task_key' }
      );

    if (error) console.error('markTaskDone:', error.message);
  } catch (error) {
    console.error('markTaskDone:', error.message);
  }
}

/* repeatable = a completion time is stored; remainingSeconds > 0 means still locked. */
async function getYoutubeLock(userId, taskKey) {
  try {
    const { data, error } = await db
      .from('trial_task_cooldowns')
      .select('completed_at')
      .eq('telegram_id', String(userId))
      .eq('task_key', taskKey)
      .maybeSingle();

    if (error || !data) {
      if (error) console.error('getYoutubeLock:', error.message);
      return { repeatable: false, remainingSeconds: 0 };
    }

    const doneAt = new Date(data.completed_at).getTime();
    if (!Number.isFinite(doneAt)) return { repeatable: false, remainingSeconds: 0 };

    const remainingMs = Math.max(0, doneAt + YOUTUBE_REPEAT_MS - Date.now());
    return { repeatable: true, remainingSeconds: Math.ceil(remainingMs / 1000) };
  } catch (error) {
    console.error('getYoutubeLock:', error.message);
    return { repeatable: false, remainingSeconds: 0 };
  }
}

async function getTaskCooldownRows(telegramId) {
  try {
    const { data, error } = await db
      .from('trial_task_cooldowns')
      .select('task_key,completed_at')
      .eq('telegram_id', String(telegramId));

    if (error) {
      console.error('getTaskCooldownRows:', error.message);
      return [];
    }

    return data || [];
  } catch (error) {
    console.error('getTaskCooldownRows:', error.message);
    return [];
  }
}

async function getAccount(tg) {
  const { data: user, error: userError } = await db
    .from('trial_users')
    .select('*')
    .eq('telegram_id', tg.id)
    .maybeSingle();

  if (userError) throw userError;
  if (!user) throw new Error('Account not initialized. Call /sync first.');

  const since = new Date(Date.now() - AD_COOLDOWN_MS).toISOString();

  const [ads, approvedTasks, referrals, payouts, taskRows, adCooldowns, cooldownRows] = await Promise.all([
    db.from('trial_ad_claims')
      .select('id', { count: 'exact', head: true })
      .eq('telegram_id', tg.id)
      .eq('verification_status', 'verified')
      .gte('created_at', since),

    db.from('trial_task_claims')
      .select('id', { count: 'exact', head: true })
      .eq('telegram_id', tg.id)
      .eq('status', 'approved'),

    db.from('trial_users')
      .select('telegram_id', { count: 'exact', head: true })
      .eq('referred_by', tg.id),

    db.from('trial_payouts')
      .select('*')
      .eq('telegram_id', tg.id)
      .order('created_at', { ascending: false })
      .limit(30),

    db.from('trial_task_claims')
      .select('task_key,status')
      .eq('telegram_id', tg.id),

    getAdCooldowns(tg.id),

    getTaskCooldownRows(tg.id)
  ]);

  for (const result of [ads, approvedTasks, referrals, payouts, taskRows]) {
    if (result.error) throw result.error;
  }

  const taskStatus = {};
  for (const row of taskRows.data || []) {
    taskStatus[row.task_key] = row.status;
  }

  /* 24h countdown for approved YouTube tasks. */
  const taskCooldowns = {};
  const nowMs = Date.now();

  for (const row of cooldownRows) {
    if (TASKS[row.task_key]?.type !== 'youtube') continue;
    if (taskStatus[row.task_key] !== 'approved') continue;

    const doneAt = new Date(row.completed_at).getTime();
    if (!Number.isFinite(doneAt)) continue;

    const availableAt = doneAt + YOUTUBE_REPEAT_MS;
    const remainingMs = Math.max(0, availableAt - nowMs);

    taskCooldowns[row.task_key] = {
      completedAt: row.completed_at,
      availableAgainAt: new Date(availableAt).toISOString(),
      remainingSeconds: Math.ceil(remainingMs / 1000)
    };
  }

  const balance = Number(user.balance_usdt || 0);
  const adsWatched = ads.count || 0;
  const tasksCompleted = approvedTasks.count || 0;

  return {
    user: {
      id: user.telegram_id,
      first_name: user.first_name,
      username: user.username
    },

    balance,
    referrals: referrals.count || 0,
    referralReward: REFERRAL_REWARD,
    referralLink: `https://t.me/${BOT_USERNAME}/Web?startapp=ref_${tg.id}`,
    referralHistory: [],
    adsWatched,
    adCooldowns,
    requiredAds: REQUIRED_ADS,
    tasksCompleted,
    requiredTasks: REQUIRED_TASKS,
    taskStatus,
    taskCooldowns,
    payouts: payouts.data || [],

    canWithdraw:
      adsWatched >= REQUIRED_ADS &&
      tasksCompleted >= REQUIRED_TASKS &&
      balance >= MIN_WITHDRAWAL,

    config: {
      appName: 'NX USDT',
      joiningBonusUSDT: JOINING_BONUS,
      referralRewardUSDT: REFERRAL_REWARD,
      taskRewardUSDT: TASK_REWARD,
      adRewardUSDT: AD_REWARD,
      minWithdrawalUSDT: MIN_WITHDRAWAL,
      maxWithdrawalUSDT: MAX_WITHDRAWAL,
      adsPer24Hours: ADS_PER_24H,
      adCooldownHours: 24,
      requiredAds: REQUIRED_ADS,
      requiredTasks: REQUIRED_TASKS,
      adsgramBlockId: ADSGRAM_BLOCK_ID,
      adClickRequired: REQUIRE_AD_CLICK,
      noClickAdSlots: NO_CLICK_AD_SLOTS,
      autoVerifyTasks: AUTO_VERIFY_TASKS,
      youtubeAutoApprove: YOUTUBE_AUTO_APPROVE,
      autoPayoutEnabled: AUTO_PAYOUT_ENABLED,
      youtubeTasks: 4
    }
  };
}

/* ---------- YouTube task timer (stateless signed token) ---------- */
const YT_TOKEN_KEY = crypto
  .createHmac('sha256', BOT_TOKEN)
  .update('youtube-task-token')
  .digest();

function signYoutubeToken(userId, taskKey, startedAt) {
  const sig = crypto
    .createHmac('sha256', YT_TOKEN_KEY)
    .update(`${userId}:${taskKey}:${startedAt}`)
    .digest('hex');

  return `${startedAt}.${sig}`;
}

function checkYoutubeToken(userId, taskKey, token) {
  const [startedRaw, sig] = String(token || '').split('.');
  const startedAt = Number(startedRaw);

  if (!Number.isFinite(startedAt) || !sig) {
    return { ok: false, error: 'Press START first.' };
  }

  const expected = signYoutubeToken(userId, taskKey, startedAt).split('.')[1];

  if (!safeEqual(sig, expected)) {
    return { ok: false, error: 'Invalid task token. Press START again.' };
  }

  const elapsed = Date.now() - startedAt;

  if (elapsed > 2 * 60 * 60 * 1000) {
    return { ok: false, error: 'Task expired. Press START again.' };
  }

  if (elapsed < YOUTUBE_WATCH_SECONDS * 1000) {
    return {
      ok: false,
      early: true,
      error: 'Verified too early. Watch the full video, then press START again.'
    };
  }

  return { ok: true };
}

/* ---------- Telegram channel membership check ---------- */
async function isChannelMember(chatId, userId) {
  const url =
    `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember` +
    `?chat_id=${encodeURIComponent(chatId)}&user_id=${encodeURIComponent(userId)}`;

  const response = await fetch(url);
  const json = await response.json();

  if (!json.ok) {
    console.error('getChatMember failed:', json.description);
    throw new Error('Could not verify channel membership.');
  }

  return ['creator', 'administrator', 'member'].includes(json.result.status);
}

/* ---------- Auto payout ---------- */
let usdtContract = null;

function getUsdtContract() {
  if (usdtContract) return usdtContract;
  if (!PAYOUT_PRIVATE_KEY) throw new Error('PAYOUT_PRIVATE_KEY is not set.');

  const provider = new ethers.JsonRpcProvider(BSC_RPC_URL);
  const wallet = new ethers.Wallet(PAYOUT_PRIVATE_KEY, provider);

  usdtContract = new ethers.Contract(
    USDT_CONTRACT,
    ['function transfer(address to, uint256 amount) returns (bool)'],
    wallet
  );

  return usdtContract;
}

async function sendPayout(payout) {
  /* Lock the row so the same payout can never be sent twice. */
  const { data: locked, error: lockError } = await db
    .from('trial_payouts')
    .update({ status: 'processing' })
    .eq('id', payout.id)
    .in('status', ['pending', 'reserved', 'failed'])
    .select('id')
    .maybeSingle();

  if (lockError) throw lockError;
  if (!locked) {
    return { success: false, error: 'Payout is already being processed or paid.' };
  }

  let txHash = null;

  try {
    const amount = ethers.parseUnits(Number(payout.amount_usdt).toFixed(2), USDT_DECIMALS);

    const tx = await getUsdtContract().transfer(payout.wallet_address, amount);
    txHash = tx.hash;

    await db.from('trial_payouts').update({ tx_hash: txHash }).eq('id', payout.id);
    await tx.wait(1);

    /* Sets status 'sent' AND deducts the user's balance in one DB transaction. */
    try {
      const marked = await rpc('trial_mark_payout_sent', {
        p_payout_id: payout.id,
        p_tx_hash: txHash
      });

      if (marked?.success !== true) {
        console.error('Payout sent but not marked in DB:', payout.id, txHash, marked);
      }
    } catch (markError) {
      console.error('Payout sent but DB update failed:', payout.id, txHash, markError.message);
    }

    return { success: true, txHash };
  } catch (error) {
    console.error('sendPayout failed:', error.message);

    if (!txHash) {
      await db.from('trial_payouts').update({ status: 'failed' }).eq('id', payout.id);
    } else {
      /* Transaction was broadcast: leave 'processing' and verify on BscScan manually. */
      console.error('Transaction was sent, verify manually:', txHash);
    }

    return { success: false, error: 'Transfer failed. Admin will review.' };
  }
}

app.get('/', (req, res) => {
  res.json({ success: true, app: 'NX USDT', status: 'online' });
});

app.get('/health', (req, res) => {
  res.json({ success: true, status: 'ok' });
});

app.post('/sync', authTelegram, async (req, res) => {
  try {
    const tg = req.telegramUser;
    const startParam = String(req.body?.startParam || tg.start_param || '');

    let referrerId = /^ref_\d{1,20}$/.test(startParam) ? startParam.slice(4) : null;
    if (referrerId === tg.id) referrerId = null;

    await rpc('trial_sync_user', {
      p_telegram_id: tg.id,
      p_first_name: tg.first_name,
      p_username: tg.username || null,
      p_photo_url: tg.photo_url || null,
      p_referrer_id: referrerId,
      p_joining_bonus: JOINING_BONUS,
      p_referral_reward: REFERRAL_REWARD
    });

    return res.json({ success: true, ...(await getAccount(tg)) });
  } catch (error) {
    console.error('/sync:', error.message);
    return fail(res, 500, 'Could not initialize account. Check Supabase RPC/table setup.');
  }
});

app.post('/account', authTelegram, async (req, res) => {
  try {
    return res.json({ success: true, ...(await getAccount(req.telegramUser)) });
  } catch (error) {
    console.error('/account:', error.message);
    return fail(res, 500, 'Could not load account.');
  }
});

/* Start an ad attempt. The SQL function must enforce cooldown atomically. */
app.post('/adsgram/start', authTelegram, async (req, res) => {
  try {
    const adId = Number(req.body?.adId);

    if (!Number.isInteger(adId) || adId < 1 || adId > ADS_PER_24H) {
      return fail(res, 400, 'Invalid ad slot.');
    }

    const cooldowns = await getAdCooldowns(req.telegramUser.id);
    const slot = cooldowns.find(item => item.adId === adId);

    if (slot?.locked) {
      return fail(res, 409, 'This ad slot is on cooldown.', {
        adId,
        locked: true,
        lastWatchedAt: slot.lastWatchedAt,
        availableAgainAt: slot.availableAgainAt,
        remainingSeconds: slot.remainingSeconds
      });
    }

    const result = await rpc('trial_start_ad_attempt', {
      p_telegram_id: req.telegramUser.id,
      p_ad_id: adId,
      p_reward_usdt: AD_REWARD,
      p_max_ads_24h: ADS_PER_24H
    });

    if (result?.success === false) {
      return fail(res, 409, result.reason || result.error || 'Ad attempt denied.', { result });
    }

    return res.json({ success: true, adId, result });
  } catch (error) {
    console.error('/adsgram/start:', error.message);
    return fail(res, 400, 'Could not start ad. Check the daily limit and RPC setup.');
  }
});

app.post('/adsgram/claim', authTelegram, async (req, res) => {
  try {
    const adId = Number(req.body?.adId);

    if (!Number.isInteger(adId) || adId < 1 || adId > ADS_PER_24H) {
      return fail(res, 400, 'Invalid ad slot.');
    }

    /* Click is required on every slot except those listed in NO_CLICK_AD_SLOTS. */
    if (adNeedsClick(adId) && req.body?.clicked !== true) {
      return fail(res, 400, 'You must click the ad button to earn the reward.', {
        clickRequired: true
      });
    }

    const cooldowns = await getAdCooldowns(req.telegramUser.id);
    const slot = cooldowns.find(item => item.adId === adId);

    if (slot?.locked) {
      return fail(res, 409, 'This ad slot has already been rewarded in the last 24 hours.', {
        adId,
        locked: true,
        availableAgainAt: slot.availableAgainAt,
        remainingSeconds: slot.remainingSeconds
      });
    }

    const result = await rpc('trial_confirm_ad_reward', {
      p_telegram_id: req.telegramUser.id,
      p_reward_usdt: AD_REWARD
    });

    if (result?.success !== true) {
      return fail(res, 409, result?.reason || 'No valid pending ad attempt.');
    }

    const account = await getAccount(req.telegramUser);
    const updatedSlot = account.adCooldowns.find(item => item.adId === adId);

    return res.json({
      success: true,
      adId,
      reward: AD_REWARD,
      balance: account.balance,
      lastWatchedAt: updatedSlot?.lastWatchedAt || null,
      availableAgainAt: updatedSlot?.availableAgainAt || null,
      remainingSeconds: updatedSlot?.remainingSeconds || 0,
      result
    });
  } catch (error) {
    console.error('/adsgram/claim:', error.message);
    return fail(res, 400, 'Could not claim ad reward.');
  }
});

/* Cancel the user's pending ad attempt (ad closed without clicking "Go!"). */
app.post('/adsgram/cancel', authTelegram, async (req, res) => {
  try {
    await rpc('trial_cancel_ad_attempt', { p_telegram_id: req.telegramUser.id });
    return res.json({ success: true });
  } catch (error) {
    console.error('/adsgram/cancel:', error.message);
    return fail(res, 500, 'Could not cancel ad attempt.');
  }
});

/* AdsGram server-to-server Reward URL callback (disabled in click-required mode). */
app.get('/adsgram/reward', async (req, res) => {
  try {
    if (REQUIRE_AD_CLICK) {
      return res.status(200).send('Ignored: click-required mode.');
    }

    if (!ADSGRAM_REWARD_SECRET) {
      return res.status(503).send('Reward callback is not configured.');
    }

    if (!safeEqual(req.query.secret, ADSGRAM_REWARD_SECRET)) {
      return res.status(401).send('Unauthorized.');
    }

    const userId = String(req.query.userid || req.query.userId || '');

    if (!/^\d{1,20}$/.test(userId)) {
      return res.status(400).send('Invalid user ID.');
    }

    const result = await rpc('trial_confirm_ad_reward', {
      p_telegram_id: userId,
      p_reward_usdt: AD_REWARD
    });

    if (result?.success !== true) {
      return res.status(409).send(String(result?.reason || 'Reward not credited.'));
    }

    return res.status(200).send('OK');
  } catch (error) {
    console.error('/adsgram/reward:', error.message);
    return res.status(500).send('Reward processing failed.');
  }
});

/* Return the latest verified claim and individual cooldown. */
app.post('/adsgram/status', authTelegram, async (req, res) => {
  try {
    const adId = Number(req.body?.adId);

    if (!Number.isInteger(adId) || adId < 1 || adId > ADS_PER_24H) {
      return fail(res, 400, 'Invalid ad slot.');
    }

    const cooldowns = await getAdCooldowns(req.telegramUser.id);
    const slot = cooldowns.find(item => item.adId === adId);
    const account = await getAccount(req.telegramUser);

    return res.json({
      success: true,
      ...(slot || {
        adId,
        verified: false,
        locked: false,
        lastWatchedAt: null,
        availableAgainAt: null,
        remainingSeconds: 0,
        reward: 0
      }),
      balance: account.balance
    });
  } catch (error) {
    console.error('/adsgram/status:', error.message);
    return fail(res, 500, 'Could not check ad status.');
  }
});

/* YouTube task: START. Returns a signed token carrying the server start time. */
app.post('/tasks/youtube/start', authTelegram, async (req, res) => {
  try {
    const taskKey = String(req.body?.taskKey || '');

    if (TASKS[taskKey]?.type !== 'youtube') {
      return fail(res, 400, 'This task is not available.');
    }

    const userId = req.telegramUser.id;

    const { data: existing } = await db
      .from('trial_task_claims')
      .select('status')
      .eq('telegram_id', userId)
      .eq('task_key', taskKey)
      .maybeSingle();

    if (existing?.status === 'approved') {
      const lock = await getYoutubeLock(userId, taskKey);

      if (!lock.repeatable) {
        return fail(res, 409, 'Task already approved.');
      }

      if (lock.remainingSeconds > 0) {
        return fail(
          res,
          409,
          `This task is available again in ${formatDuration(lock.remainingSeconds)}.`,
          { remainingSeconds: lock.remainingSeconds }
        );
      }
    }

    const startedAt = Date.now();

    return res.json({
      success: true,
      token: signYoutubeToken(userId, taskKey, startedAt),
      waitSeconds: YOUTUBE_WATCH_SECONDS
    });
  } catch (error) {
    console.error('/tasks/youtube/start:', error.message);
    return fail(res, 400, 'Could not start task.');
  }
});

app.post('/tasks/submit', authTelegram, async (req, res) => {
  try {
    const taskKey = String(req.body?.taskKey || '');
    const task = TASKS[taskKey];

    if (!task) return fail(res, 400, 'This task is not available.');

    const userId = req.telegramUser.id;

    const { data: existing } = await db
      .from('trial_task_claims')
      .select('status')
      .eq('telegram_id', userId)
      .eq('task_key', taskKey)
      .maybeSingle();

    /* Approved YouTube tasks can be repeated once their 24h lock has passed. */
    let renewing = false;

    if (existing?.status === 'approved') {
      if (task.type !== 'youtube') {
        return fail(res, 409, 'Task already approved.');
      }

      const lock = await getYoutubeLock(userId, taskKey);

      if (!lock.repeatable) {
        return fail(res, 409, 'Task already approved.');
      }

      if (lock.remainingSeconds > 0) {
        return fail(
          res,
          409,
          `This task is available again in ${formatDuration(lock.remainingSeconds)}.`,
          { remainingSeconds: lock.remainingSeconds }
        );
      }

      renewing = true;
    }

    if (task.type === 'telegram' && AUTO_VERIFY_TASKS) {
      const member = await isChannelMember(task.chat, userId);

      if (!member) {
        return fail(res, 400, 'Join the channel first, then press START and VERIFY again.');
      }

      /* May already exist as 'pending' from an older submission, so don't fail on it. */
      try {
        await rpc('trial_submit_task', { p_telegram_id: userId, p_task_key: taskKey });
      } catch (submitError) {
        console.warn('trial_submit_task skipped:', submitError.message);
      }

      const review = await rpc('trial_review_task', {
        p_telegram_id: userId,
        p_task_key: taskKey,
        p_decision: 'approve',
        p_reward: TASK_REWARD
      });

      return res.json({
        success: true,
        result: review,
        message: 'Channel verified. Reward added!'
      });
    }

    if (task.type === 'youtube') {
      const check = checkYoutubeToken(userId, taskKey, req.body?.token);

      if (!check.ok) {
        return fail(res, 400, check.error, { early: Boolean(check.early) });
      }

      if (existing?.status === 'pending' && !YOUTUBE_AUTO_APPROVE) {
        return fail(res, 409, 'Task already submitted. Waiting for admin verification.');
      }

      /* New 24h round: clear the old approved claim so it can be submitted again. */
      if (renewing) {
        const { error: clearError } = await db
          .from('trial_task_claims')
          .delete()
          .eq('telegram_id', userId)
          .eq('task_key', taskKey);

        if (clearError) throw clearError;
      }

      /* May already exist as 'pending' from an older submission, so don't fail on it. */
      try {
        await rpc('trial_submit_task', { p_telegram_id: userId, p_task_key: taskKey });
      } catch (submitError) {
        console.warn('trial_submit_task skipped:', submitError.message);
      }

      if (YOUTUBE_AUTO_APPROVE) {
        const review = await rpc('trial_review_task', {
          p_telegram_id: userId,
          p_task_key: taskKey,
          p_decision: 'approve',
          p_reward: TASK_REWARD
        });

        if (review?.success !== false) {
          await markTaskDone(userId, taskKey);
        }

        return res.json({
          success: true,
          result: review,
          message: 'Video verified. Reward added!'
        });
      }

      return res.json({
        success: true,
        message: 'Submitted for admin verification.'
      });
    }

    if (existing?.status === 'pending') {
      return fail(res, 409, 'Task already submitted. Waiting for admin verification.');
    }

    const result = await rpc('trial_submit_task', {
      p_telegram_id: userId,
      p_task_key: taskKey
    });

    return res.json({
      success: true,
      result,
      message: 'Submitted for admin verification.'
    });
  } catch (error) {
    console.error('/tasks/submit:', error.message);
    return fail(
      res,
      400,
      error.message === 'Could not verify channel membership.'
        ? error.message
        : 'Could not submit task.'
    );
  }
});

app.post('/admin/task/review', authAdmin, async (req, res) => {
  try {
    const telegramId = String(req.body?.telegramId || '');
    const taskKey = String(req.body?.taskKey || '');
    const decision = String(req.body?.decision || '');

    if (
      !/^\d{1,20}$/.test(telegramId) ||
      !TASK_KEYS.includes(taskKey) ||
      !['approve', 'reject'].includes(decision)
    ) {
      return fail(res, 400, 'Invalid review data.');
    }

    const result = await rpc('trial_review_task', {
      p_telegram_id: telegramId,
      p_task_key: taskKey,
      p_decision: decision,
      p_reward: TASK_REWARD
    });

    if (decision === 'approve' && result?.success !== false) {
      await markTaskDone(telegramId, taskKey);
    }

    return res.json({ success: true, result });
  } catch (error) {
    console.error('/admin/task/review:', error.message);
    return fail(res, 400, 'Could not review task.');
  }
});

app.post('/payouts', authTelegram, async (req, res) => {
  try {
    const { data, error } = await db
      .from('trial_payouts')
      .select('*')
      .eq('telegram_id', req.telegramUser.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    return res.json({ success: true, payouts: data || [] });
  } catch (error) {
    console.error('/payouts:', error.message);
    return fail(res, 500, 'Could not load payout history.');
  }
});

app.post('/payout', authTelegram, async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    const walletAddress = String(req.body?.walletAddress || req.body?.wallet || '').trim();

    const maximum = Math.min(MAX_WITHDRAWAL, Number(process.env.PAYOUT_MAX_USDT || 100));

    if (!Number.isFinite(amount) || amount < MIN_WITHDRAWAL || amount > maximum) {
      return fail(
        res,
        400,
        `Withdrawal amount must be between ${MIN_WITHDRAWAL} and ${maximum} USDT.`
      );
    }

    if (!ethers.isAddress(walletAddress)) {
      return fail(res, 400, 'Enter a valid BEP-20 wallet address.');
    }

    const account = await getAccount(req.telegramUser);

    if (!account.canWithdraw) {
      return fail(res, 403, 'Withdrawal requirements are not complete.', {
        requiredAds: REQUIRED_ADS,
        adsWatched: account.adsWatched,
        requiredTasks: REQUIRED_TASKS,
        tasksCompleted: account.tasksCompleted,
        minimum: MIN_WITHDRAWAL,
        balance: account.balance
      });
    }

    const result = await rpc('trial_request_payout', {
      p_telegram_id: req.telegramUser.id,
      p_amount_usdt: amount,
      p_wallet_address: walletAddress
    });

    if (result?.success === false) {
      return fail(res, 400, result.error || 'Withdrawal request rejected.', { result });
    }

    let message = 'Withdrawal request saved. It will be reviewed shortly.';
    let status = 'pending';
    let txHash = null;

    if (AUTO_PAYOUT_ENABLED && amount <= AUTO_PAYOUT_MAX_USDT) {
      const { data: row } = await db
        .from('trial_payouts')
        .select('*')
        .eq('id', result?.payout_id)
        .eq('telegram_id', req.telegramUser.id)
        .eq('status', 'pending')
        .maybeSingle();

      if (row) {
        const sent = await sendPayout(row);

        if (sent.success) {
          status = 'sent';
          txHash = sent.txHash;
          message = 'Withdrawal sent to your wallet!';
        } else {
          message = 'Withdrawal saved. Automatic transfer failed, admin will process it.';
        }
      }
    }

    return res.json({
      success: true,
      result,
      status,
      txHash,
      automaticPayoutEnabled: AUTO_PAYOUT_ENABLED,
      message
    });
  } catch (error) {
    console.error('/payout:', error.message);
    return fail(
      res,
      400,
      'Could not create withdrawal request. Check eligibility and Supabase RPC.'
    );
  }
});

/* Manual send for large amounts or retrying a failed payout. */
app.post('/admin/payout/process', authAdmin, async (req, res) => {
  try {
    const payoutId = req.body?.payoutId;
    if (!payoutId) return fail(res, 400, 'payoutId is required.');

    const { data: row, error } = await db
      .from('trial_payouts')
      .select('*')
      .eq('id', payoutId)
      .maybeSingle();

    if (error || !row) return fail(res, 404, 'Payout not found.');

    const sent = await sendPayout(row);
    return sent.success ? res.json({ success: true, ...sent }) : fail(res, 400, sent.error);
  } catch (error) {
    console.error('/admin/payout/process:', error.message);
    return fail(res, 500, 'Could not process payout.');
  }
});
/* =====================================================================
   BROADCAST (admin only)
   Paste this block in index.js ABOVE the line:
     app.use((req, res) => { return fail(res, 404, 'API endpoint not found.'); });
   ===================================================================== */

let broadcastRunning = false;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/* All user IDs from trial_users, fetched in pages of 1000. */
async function getAllUserIds() {
  const ids = [];
  const page = 1000;

  for (let from = 0; ; from += page) {
    const { data, error } = await db
      .from('trial_users')
      .select('telegram_id')
      .order('telegram_id')
      .range(from, from + page - 1);

    if (error) throw error;

    for (const row of data || []) ids.push(String(row.telegram_id));
    if (!data || data.length < page) break;
  }

  return ids;
}

async function sendTelegramMessage(chatId, text, button) {
  const body = { chat_id: chatId, text, disable_web_page_preview: true };

  if (button?.text && button?.url) {
    body.reply_markup = { inline_keyboard: [[{ text: button.text, url: button.url }]] };
  }

  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  return response.json();
}

async function runBroadcast(ids, text, button) {
  let sent = 0;
  let blocked = 0;
  let failed = 0;

  for (const id of ids) {
    try {
      let result = await sendTelegramMessage(id, text, button);

      /* Telegram asks us to slow down: wait, then retry once. */
      if (!result.ok && result.error_code === 429) {
        await sleep((Number(result.parameters?.retry_after) || 5) * 1000 + 500);
        result = await sendTelegramMessage(id, text, button);
      }

      if (result.ok) sent++;
      else if (result.error_code === 403) blocked++; /* user blocked the bot or never started it */
      else {
        failed++;
        console.warn('Broadcast failed for', id, result.description);
      }
    } catch (error) {
      failed++;
      console.warn('Broadcast error for', id, error.message);
    }

    await sleep(50); /* about 20 messages per second, under Telegram's limit */
  }

  console.log(`Broadcast finished. Total: ${ids.length}, sent: ${sent}, blocked/not started: ${blocked}, failed: ${failed}`);
}

/*
  Body (JSON):
    message     required, up to 4000 characters
    buttonText  optional, e.g. "Open NX USDT"
    buttonUrl   optional, defaults to your Mini App link when buttonText is given
    testId      optional, send ONLY to this Telegram ID (use it to test first)
*/
app.post('/admin/broadcast', authAdmin, async (req, res) => {
  try {
    const message = String(req.body?.message || '').trim();
    const buttonText = String(req.body?.buttonText || '').trim().slice(0, 64);
    const buttonUrl = String(req.body?.buttonUrl || `https://t.me/${BOT_USERNAME}/Web`).trim();
    const testId = req.body?.testId ? String(req.body.testId) : null;

    if (!message || message.length > 4000) {
      return fail(res, 400, 'Message is required (max 4000 characters).');
    }

    if (testId && !/^\d{1,20}$/.test(testId)) {
      return fail(res, 400, 'Invalid testId.');
    }

    if (buttonText && !/^https:\/\//.test(buttonUrl)) {
      return fail(res, 400, 'buttonUrl must start with https://');
    }

    if (broadcastRunning) {
      return fail(res, 409, 'A broadcast is already running.');
    }

    const ids = testId ? [testId] : await getAllUserIds();
    const button = buttonText ? { text: buttonText, url: buttonUrl } : null;

    broadcastRunning = true;

    /* Reply right away; sending continues in the background. Result is in Railway logs. */
    res.json({ success: true, recipients: ids.length, message: 'Broadcast started. Check Railway logs for the result.' });

    runBroadcast(ids, message, button)
      .catch(error => console.error('Broadcast crashed:', error.message))
      .finally(() => { broadcastRunning = false; });
  } catch (error) {
    console.error('/admin/broadcast:', error.message);
    return fail(res, 500, 'Could not start broadcast.');
  }
});
app.use((req, res) => {
  return fail(res, 404, 'API endpoint not found.');
});

app.use((error, req, res, next) => {
  console.error('Unhandled API error:', error.message);
  if (res.headersSent) return next(error);
  return fail(res, 500, 'Internal server error.');
});

app.listen(PORT, () => {
  console.log(`NX USDT API listening on port ${PORT}`);
});
