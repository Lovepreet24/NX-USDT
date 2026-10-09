/*
 * NX USDT backend — index.js
 *
 * Required Railway variables:
 * BOT_TOKEN
 * BOT_USERNAME
 * SUPABASE_URL
 * SUPABASE_SERVICE_ROLE_KEY
 * ADSGRAM_REWARD_SECRET
 * ADMIN_SECRET
 *
 * Keep PAYOUT_MODE=disabled until live payout processing
 * has been implemented, tested, and audited.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

const PORT = Number(process.env.PORT || 3000);
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
const REQUIRED_TASKS = Number(
  process.env.REQUIRED_SOCIAL_TASKS_TO_WITHDRAW || 2
);

const ADSGRAM_BLOCK_ID = String(process.env.ADSGRAM_BLOCK_ID || '52783');
const ADSGRAM_REWARD_SECRET = process.env.ADSGRAM_REWARD_SECRET || '';
const ADS_PER_24H = 12;

const PAYOUT_MODE = String(
  process.env.PAYOUT_MODE || 'disabled'
).toLowerCase();

const PAYOUT_RPC_URL = process.env.PAYOUT_RPC_URL || '';
const PAYOUT_PRIVATE_KEY = process.env.PAYOUT_PRIVATE_KEY || '';
const PAYOUT_CONTRACT_ADDRESS = process.env.PAYOUT_CONTRACT_ADDRESS || '';
const PAYOUT_CHAIN_ID = Number(process.env.PAYOUT_CHAIN_ID || 56);
const PAYOUT_MAX_USDT = Number(process.env.PAYOUT_MAX_USDT || 100);

const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    'Missing BOT_TOKEN, SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY'
  );
  process.exit(1);
}

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      ALLOWED_ORIGINS.length === 0 ||
      ALLOWED_ORIGINS.includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'x-telegram-init-data',
    'x-admin-secret'
  ]
}));

function fail(res, status, error, extra = {}) {
  return res.status(status).json({
    success: false,
    error,
    ...extra
  });
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));

  return (
    x.length === y.length &&
    x.length > 0 &&
    crypto.timingSafeEqual(x, y)
  );
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
    throw new Error(
      'Open NX USDT through Telegram Mini App.'
    );
  }

  const params = new URLSearchParams(raw);
  const hash = params.get('hash');

  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) {
    throw new Error('Invalid Telegram authentication data.');
  }

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isFinite(authDate) ||
    authDate > now + 60 ||
    now - authDate > 3600
  ) {
    throw new Error(
      'Telegram session expired. Reopen the Mini App.'
    );
  }

  const pairs = [];

  for (const [key, value] of params.entries()) {
    if (key !== 'hash') {
      pairs.push([key, value]);
    }
  }

  pairs.sort(([a], [b]) => a.localeCompare(b));

  const checkString = pairs
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac('sha256', secretKey)
    .update(checkString)
    .digest('hex');

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
  if (!ADMIN_SECRET) {
    return fail(res, 503, 'Admin controls are disabled.');
  }

  if (!safeEqual(req.headers['x-admin-secret'], ADMIN_SECRET)) {
    return fail(res, 401, 'Unauthorized admin request.');
  }

  next();
}

async function rpc(name, args) {
  const { data, error } = await db.rpc(name, args);

  if (error) {
    throw error;
  }

  return data;
}

async function getAccount(tg) {
  const {
    data: user,
    error: userError
  } = await db
    .from('trial_users')
    .select('*')
    .eq('telegram_id', tg.id)
    .maybeSingle();

  if (userError) {
    throw userError;
  }

  if (!user) {
    throw new Error('Account not initialized. Call /sync first.');
  }

  const since = new Date(
    Date.now() - 24 * 60 * 60 * 1000
  ).toISOString();

  const [
    ads,
    approvedTasks,
    referrals,
    payouts,
    taskRows
  ] = await Promise.all([
    db
      .from('trial_ad_claims')
      .select('id', { count: 'exact', head: true })
      .eq('telegram_id', tg.id)
      .eq('verification_status', 'verified')
      .gte('created_at', since),

    db
      .from('trial_task_claims')
      .select('id', { count: 'exact', head: true })
      .eq('telegram_id', tg.id)
      .eq('status', 'approved'),

    db
      .from('trial_users')
      .select('telegram_id', { count: 'exact', head: true })
      .eq('referred_by', tg.id),

    db
      .from('trial_payouts')
      .select('*')
      .eq('telegram_id', tg.id)
      .order('created_at', { ascending: false })
      .limit(30),

    db
      .from('trial_task_claims')
      .select('task_key,status')
      .eq('telegram_id', tg.id)
  ]);

  for (const result of [
    ads,
    approvedTasks,
    referrals,
    payouts,
    taskRows
  ]) {
    if (result.error) {
      throw result.error;
    }
  }

  const taskStatus = {};

  for (const row of taskRows.data || []) {
    taskStatus[row.task_key] = row.status;
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

    referralLink:
      `https://t.me/${BOT_USERNAME}/Web?startapp=ref_${tg.id}`,

    referralHistory: [],
    adsWatched,
    requiredAds: REQUIRED_ADS,
    tasksCompleted,
    requiredTasks: REQUIRED_TASKS,
    taskStatus,
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
      requiredAds: REQUIRED_ADS,
      requiredTasks: REQUIRED_TASKS,
      adsgramBlockId: ADSGRAM_BLOCK_ID,
      youtubeTasksComingSoon: 4
    }
  };
}

app.get('/', (req, res) => {
  res.json({
    success: true,
    app: 'NX USDT',
    status: 'online'
  });
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'ok'
  });
});

/*
 * Initialize or synchronize the Telegram user.
 * Requires Supabase RPC: trial_sync_user.
 */
app.post('/sync', authTelegram, async (req, res) => {
  try {
    const tg = req.telegramUser;

    const startParam = String(
      req.body?.startParam || tg.start_param || ''
    );

    let referrerId = /^ref_\d{1,20}$/.test(startParam)
      ? startParam.slice(4)
      : null;

    if (referrerId === tg.id) {
      referrerId = null;
    }

    await rpc('trial_sync_user', {
      p_telegram_id: tg.id,
      p_first_name: tg.first_name,
      p_username: tg.username || null,
      p_photo_url: tg.photo_url || null,
      p_referrer_id: referrerId,
      p_joining_bonus: JOINING_BONUS,
      p_referral_reward: REFERRAL_REWARD
    });

    return res.json({
      success: true,
      ...(await getAccount(tg))
    });
  } catch (error) {
    console.error('/sync:', error.message);

    return fail(
      res,
      500,
      'Could not initialize account. Check Supabase RPC/table setup.'
    );
  }
});

app.post('/account', authTelegram, async (req, res) => {
  try {
    return res.json({
      success: true,
      ...(await getAccount(req.telegramUser))
    });
  } catch (error) {
    console.error('/account:', error.message);
    return fail(res, 500, 'Could not load account.');
  }
});

/*
 * Start an ad attempt.
 * Requires Supabase RPC: trial_start_ad_attempt.
 */
app.post('/adsgram/start', authTelegram, async (req, res) => {
  try {
    const tg = req.telegramUser;
    const adId = Number(req.body?.adId);

    if (
      !Number.isInteger(adId) ||
      adId < 1 ||
      adId > ADS_PER_24H
    ) {
      return fail(res, 400, 'Invalid ad slot.');
    }

    const result = await rpc('trial_start_ad_attempt', {
      p_telegram_id: tg.id,
      p_ad_id: adId,
      p_reward_usdt: AD_REWARD,
      p_max_ads_24h: ADS_PER_24H
    });

    return res.json({
      success: true,
      result
    });
  } catch (error) {
    console.error('/adsgram/start:', error.message);

    return fail(
      res,
      400,
      'Could not start ad. You may have reached the 24-hour limit or database RPC setup is missing.'
    );
  }
});

/*
 * AdsGram server-to-server Reward URL.
 *
 * Configure the URL in AdsGram using your own secret:
 * https://nx-usdt-production.up.railway.app/adsgram/reward?secret=YOUR_SECRET&userid=[userId]
 *
 * Keep the secret in Railway and AdsGram settings only.
 * Never put it in index.html.
 *
 * Requires Supabase RPC: trial_confirm_ad_reward.
 */
app.get('/adsgram/reward', async (req, res) => {
  try {
    if (!ADSGRAM_REWARD_SECRET) {
      return res.status(503).send(
        'reward endpoint not configured'
      );
    }

    if (!safeEqual(req.query.secret, ADSGRAM_REWARD_SECRET)) {
      return res.status(401).send('unauthorized');
    }

    const userId = String(
      req.query.userid || req.query.user_id || ''
    );

    if (!/^\d{1,20}$/.test(userId)) {
      return res.status(400).send('invalid userid');
    }

    const result = await rpc('trial_confirm_ad_reward', {
      p_telegram_id: userId,
      p_reward_usdt: AD_REWARD
    });

    if (result?.success === false) {
      return res.status(409).send(
        String(result.reason || 'not credited')
      );
    }

    return res.status(200).send('OK');
  } catch (error) {
    console.error('/adsgram/reward:', error.message);
    return res.status(500).send('reward processing failed');
  }
});

/*
 * Check whether the latest attempt for a slot was verified.
 * This endpoint does not itself credit money.
 */
app.post('/adsgram/status', authTelegram, async (req, res) => {
  try {
    const adId = Number(req.body?.adId);

    if (
      !Number.isInteger(adId) ||
      adId < 1 ||
      adId > ADS_PER_24H
    ) {
      return fail(res, 400, 'Invalid ad slot.');
    }

    const { data, error } = await db
      .from('trial_ad_claims')
      .select('verification_status,created_at,reward_usdt')
      .eq('telegram_id', req.telegramUser.id)
      .eq('ad_id', adId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!data) {
      return fail(res, 404, 'No ad attempt found.');
    }

    const account = await getAccount(req.telegramUser);

    return res.json({
      success: true,
      verified: data.verification_status === 'verified',
      reward:
        data.verification_status === 'verified'
          ? Number(data.reward_usdt || AD_REWARD)
          : 0,
      balance: account.balance,
      verificationStatus: data.verification_status
    });
  } catch (error) {
    console.error('/adsgram/status:', error.message);
    return fail(res, 500, 'Could not check ad status.');
  }
});

/*
 * Submit Telegram tasks for admin review.
 * Requires Supabase RPC: trial_submit_task.
 */
app.post('/tasks/submit', authTelegram, async (req, res) => {
  try {
    const taskKey = String(req.body?.taskKey || '');

    if (!['telegram_earn', 'telegram_payout'].includes(taskKey)) {
      return fail(res, 400, 'This task is not available yet.');
    }

    const result = await rpc('trial_submit_task', {
      p_telegram_id: req.telegramUser.id,
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
      'Task already submitted or database setup is incomplete.'
    );
  }
});

/*
 * Admin reviews submitted tasks.
 * Configure ADMIN_SECRET in Railway.
 * Requires Supabase RPC: trial_review_task.
 */
app.post('/admin/task/review', authAdmin, async (req, res) => {
  try {
    const telegramId = String(req.body?.telegramId || '');
    const taskKey = String(req.body?.taskKey || '');
    const decision = String(req.body?.decision || '');

    if (
      !/^\d{1,20}$/.test(telegramId) ||
      !['telegram_earn', 'telegram_payout'].includes(taskKey) ||
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

    return res.json({
      success: true,
      result
    });
  } catch (error) {
    console.error('/admin/task/review:', error.message);
    return fail(res, 400, 'Could not review task.');
  }
});

/*
 * Retrieve payout history.
 */
app.post('/payouts', authTelegram, async (req, res) => {
  try {
    const { data, error } = await db
      .from('trial_payouts')
      .select('*')
      .eq('telegram_id', req.telegramUser.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      throw error;
    }

    return res.json({
      success: true,
      payouts: data || []
    });
  } catch (error) {
    console.error('/payouts:', error.message);
    return fail(res, 500, 'Could not load payout history.');
  }
});

/*
 * Create a withdrawal request.
 *
 * Requires Supabase RPC: trial_request_payout.
 * This only records a request. It does NOT send USDT.
 */
app.post('/payout', authTelegram, async (req, res) => {
  try {
    const amount = Number(req.body?.amount);

    const walletAddress = String(
      req.body?.walletAddress || req.body?.wallet || ''
    ).trim();

    const maximum = Math.min(
      MAX_WITHDRAWAL,
      PAYOUT_MAX_USDT
    );

    if (
      !Number.isFinite(amount) ||
      amount < MIN_WITHDRAWAL ||
      amount > maximum
    ) {
      return fail(
        res,
        400,
        `Withdrawal amount must be between ${MIN_WITHDRAWAL} and ${maximum} USDT.`
      );
    }

    if (!ethers.isAddress(walletAddress)) {
      return fail(
        res,
        400,
        'Enter a valid BEP-20 wallet address.'
      );
    }

    const account = await getAccount(req.telegramUser);

    if (!account.canWithdraw) {
      return fail(
        res,
        403,
        'Withdrawal requirements are not complete.',
        {
          requiredAds: REQUIRED_ADS,
          adsWatched: account.adsWatched,
          requiredTasks: REQUIRED_TASKS,
          tasksCompleted: account.tasksCompleted,
          minimum: MIN_WITHDRAWAL,
          balance: account.balance
        }
      );
    }

    const result = await rpc('trial_request_payout', {
      p_telegram_id: req.telegramUser.id,
      p_amount_usdt: amount,
      p_wallet_address: walletAddress,
      p_min_withdrawal: MIN_WITHDRAWAL,
      p_max_withdrawal: maximum,
      p_required_ads: REQUIRED_ADS,
      p_required_tasks: REQUIRED_TASKS
    });

    return res.json({
      success: true,
      result,
      status: 'pending',
      automaticPayoutEnabled: false,
      message:
        'Withdrawal request saved. It will not be transferred until the payout worker is enabled and tested.'
    });
  } catch (error) {
    console.error('/payout:', error.message);

    return fail(
      res,
      400,
      'Could not create withdrawal request. Ensure payout SQL RPC is installed and balance/eligibility requirements are met.'
    );
  }
});

/*
 * Intentionally disabled:
 * Do not send real USDT until an audited, idempotent payout worker,
 * balance reservation, transaction reconciliation and failure recovery
 * have been implemented and tested.
 */
app.post('/admin/payout/process', authAdmin, async (req, res) => {
  return fail(
    res,
    503,
    'Live transfer worker is not enabled. Implement and audit payout processing and reconciliation before sending real USDT.'
  );
});

/*
 * Handle unknown endpoints.
 */
app.use((req, res) => {
  return fail(res, 404, 'API endpoint not found.');
});

/*
 * Handle unexpected server errors.
 */
app.use((error, req, res, next) => {
  console.error('Unhandled API error:', error.message);

  if (res.headersSent) {
    return next(error);
  }

  return fail(res, 500, 'Internal server error.');
});

/*
 * Start server.
 */
app.listen(PORT, () => {
  console.log(`NX USDT API listening on port ${PORT}`);
});
