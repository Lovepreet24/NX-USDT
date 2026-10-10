'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const WebSocket = require('ws');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

const PORT = Number(process.env.PORT || 8080);

const BOT_TOKEN = process.env.BOT_TOKEN;
const BOT_USERNAME = String(
  process.env.BOT_USERNAME || 'NXCoinRobot'
).replace(/^@/, '');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const JOINING_BONUS = Number(
  process.env.JOINING_BONUS_USDT || 10
);
const REFERRAL_REWARD = Number(
  process.env.REFERRAL_REWARD_USDT || 5
);
const TASK_REWARD = Number(
  process.env.TASK_REWARD_USDT || 0.25
);
const AD_REWARD = Number(
  process.env.AD_REWARD_USDT || 0.25
);
const MIN_WITHDRAWAL = Number(
  process.env.MIN_WITHDRAWAL_USDT || 5
);
const MAX_WITHDRAWAL = Number(
  process.env.MAX_WITHDRAWAL_USDT || 100
);
const REQUIRED_ADS = Number(
  process.env.REQUIRED_ADS_TO_WITHDRAW || 5
);
const REQUIRED_TASKS = Number(
  process.env.REQUIRED_SOCIAL_TASKS_TO_WITHDRAW || 2
);
const ADSGRAM_BLOCK_ID = String(
  process.env.ADSGRAM_BLOCK_ID || '52783'
);
const ADSGRAM_REWARD_SECRET =
  process.env.ADSGRAM_REWARD_SECRET || '';
const ADS_PER_24H = 12;
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ||
  'https://nxcoin.vercel.app'
)
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

if (
  !BOT_TOKEN ||
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY
) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

if (
  !Number.isFinite(AD_REWARD) ||
  AD_REWARD <= 0 ||
  !Number.isFinite(TASK_REWARD) ||
  TASK_REWARD <= 0
) {
  console.error('Invalid reward configuration.');
  process.exit(1);
}

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    },
    realtime: {
      transport: WebSocket
    }
  }
);

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS.'));
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
    x.length > 0 &&
    x.length === y.length &&
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

  if (!safeEqual(
    hash.toLowerCase(),
    calculatedHash.toLowerCase()
  )) {
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
    start_param: String(
      params.get('start_param') || ''
    ).slice(0, 150)
  };
}

function authTelegram(req, res, next) {
  try {
    req.telegramUser = verifyTelegramInitData(
      getInitData(req)
    );

    next();
  } catch (error) {
    return fail(res, 401, error.message);
  }
}

function authAdmin(req, res, next) {
  if (!ADMIN_SECRET) {
    return fail(res, 503, 'Admin controls are disabled.');
  }

  if (!safeEqual(
    req.headers['x-admin-secret'],
    ADMIN_SECRET
  )) {
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

async function getAccount(tg) {
  const { data: user, error: userError } = await db
    .from('trial_users')
    .select('*')
    .eq('telegram_id', tg.id)
    .maybeSingle();

  if (userError) throw userError;

  if (!user) {
    throw new Error(
      'Account not initialized. Call /sync first.'
    );
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
      .eq('
