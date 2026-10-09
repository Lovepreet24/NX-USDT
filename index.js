'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { ethers } = require('ethers');

const app = express();

app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

// ==========================================
// CONFIGURATION
// ==========================================

const PORT = process.env.PORT || 3000;

const BOT_TOKEN = process.env.BOT_TOKEN;
const BOT_USERNAME = (process.env.BOT_USERNAME || 'NXCoinRobot')
    .replace(/^@/, '');

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

const ADSGRAM_BLOCK_ID =
    process.env.ADSGRAM_BLOCK_ID || '52783';

const PAYOUT_MODE =
    (process.env.PAYOUT_MODE || 'disabled').toLowerCase();

const PAYOUT_RPC_URL =
    process.env.PAYOUT_RPC_URL || '';

const PAYOUT_PRIVATE_KEY =
    process.env.PAYOUT_PRIVATE_KEY || '';

const PAYOUT_CONTRACT_ADDRESS =
    process.env.PAYOUT_CONTRACT_ADDRESS || '';

const PAYOUT_CHAIN_ID =
    Number(process.env.PAYOUT_CHAIN_ID || 56);

const PAYOUT_MAX_USDT =
    Number(process.env.PAYOUT_MAX_USDT || 100);

const ADMIN_SECRET =
    process.env.ADMIN_SECRET || '';

const ALLOWED_ORIGINS = (
    process.env.ALLOWED_ORIGINS || ''
)
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

// ==========================================
// CORS
// ==========================================

app.use(cors({
    origin: (origin, callback) => {
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
        'x-admin-secret'
    ]
}));

// ==========================================
// ENVIRONMENT CHECK
// ==========================================

if (
    !BOT_TOKEN ||
    !SUPABASE_URL ||
    !SUPABASE_SERVICE_ROLE_KEY
) {
    console.error(
        'Missing BOT_TOKEN, SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY'
    );

    process.exit(1);
}

// ==========================================
// SUPABASE CONNECTION
// ==========================================

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

// ==========================================
// COMMON RESPONSE
// ==========================================

function sendError(res, status, message) {
    return res.status(status).json({
        success: false,
        error: message
    });
}

// ==========================================
// TELEGRAM MINI APP AUTHENTICATION
// ==========================================

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
    const receivedHash = params.get('hash');

    if (
        !receivedHash ||
        !/^[a-f0-9]{64}$/i.test(receivedHash)
    ) {
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

    const entries = [];

    for (const [key, value] of params.entries()) {
        if (key !== 'hash') {
            entries.push([key, value]);
        }
    }

    entries.sort(([a], [b]) => a.localeCompare(b));

    const dataCheckString = entries
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');

    const secretKey = crypto
        .createHmac('sha256', 'WebAppData')
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash = crypto
        .createHmac('sha256', secretKey)
        .update(dataCheckString)
        .digest('hex');

    const received = Buffer.from(receivedHash, 'hex');
    const calculated = Buffer.from(calculatedHash, 'hex');

    if (
        received.length !== calculated.length ||
        !crypto.timingSafeEqual(received, calculated)
    ) {
        throw new Error(
            'Telegram authentication failed.'
        );
    }

    let user;

    try {
        user = JSON.parse(params.get('user') || 'null');
    } catch {
        throw new Error('Invalid Telegram user data.');
    }

    if (
        !user ||
        !/^\d{1,20}$/.test(String(user.id))
    ) {
        throw new Error('Telegram user ID is missing.');
    }

    return {
        id: String(user.id),

        first_name: String(
            user.first_name || ''
        ).slice(0, 100),

        username: String(
            user.username || ''
        ).slice(0, 100),

        photo_url: String(
            user.photo_url || ''
        ).slice(0, 1000),

        start_param: String(
            params.get('start_param') || ''
        ).slice(0, 150)
    };
}

// ==========================================
// USER AUTH MIDDLEWARE
// ==========================================

function authenticateTelegram(req, res, next) {
    try {
        req.telegramUser = verifyTelegramInitData(
            getInitData(req)
        );

        next();
    } catch (error) {
        return sendError(
            res,
            401,
            error.message
        );
    }
}

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

function authenticateAdmin(req, res, next) {
    if (!ADMIN_SECRET) {
        return sendError(
            res,
            503,
            'Admin controls are disabled.'
        );
    }

    const received = Buffer.from(
        String(req.headers['x-admin-secret'] || '')
    );

    const expected = Buffer.from(ADMIN_SECRET);

    if (
        received.length !== expected.length ||
        !crypto.timingSafeEqual(received, expected)
    ) {
        return sendError(
            res,
            401,
            'Unauthorized admin request.'
        );
    }

    next();
}

// ==========================================
// ACCOUNT INFORMATION
// ==========================================

async function getAccount(telegramUser) {
    const telegramId = telegramUser.id;

    const {
        data: user,
        error: userError
    } = await db
        .from('trial_users')
        .select('*')
        .eq('telegram_id', telegramId)
        .maybeSingle();

    if (userError) {
        throw userError;
    }

    if (!user) {
        throw new Error(
            'Account not initialized. Call /sync first.'
        );
    }

    const since24Hours = new Date(
        Date.now() - 24 * 60 * 60 * 1000
    ).toISOString();

    const [
        adsResult,
        tasksResult,
        referralsResult,
        payoutsResult,
        taskRowsResult
    ] = await Promise.all([

        db
            .from('trial_ad_claims')
            .select('id', {
                count: 'exact',
                head: true
            })
            .eq('telegram_id', telegramId)
            .gte('created_at', since24Hours),

        db
            .from('trial_task_claims')
            .select('id', {
                count: 'exact',
                head: true
            })
            .eq('telegram_id', telegramId)
            .eq('status', 'approved'),

        db
            .from('trial_users')
            .select('telegram_id', {
                count: 'exact',
                head: true
            })
            .eq('referred_by', telegramId),

        db
            .from('trial_payouts')
            .select('*')
            .eq('telegram_id', telegramId)
            .order('created_at', {
                ascending: false
            })
            .limit(30),

        db
            .from('trial_task_claims')
            .select('task_key,status')
            .eq('telegram_id', telegramId)
    ]);

    const results = [
        adsResult,
        tasksResult,
        referralsResult,
        payoutsResult,
        taskRowsResult
    ];

    for (const result of results) {
        if (result.error) {
            throw result.error;
        }
    }

    const taskStatus = {};

    for (const task of taskRowsResult.data || []) {
        taskStatus[task.task_key] = task.status;
    }

    const adsWatched = adsResult.count || 0;
    const tasksCompleted = tasksResult.count || 0;
    const balance = Number(user.balance_usdt);

    return {
        user: {
            id: user.telegram_id,
            first_name: user.first_name,
            username: user.username
        },

        balance,

        referrals: referralsResult.count || 0,

        referralReward: REFERRAL_REWARD,

        referralLink:
            `https://t.me/${BOT_USERNAME}/Web?startapp=ref_${telegramId}`,

        referralHistory: [],

        adsWatched,

        requiredAds: REQUIRED_ADS,

        tasksCompleted,

        requiredTasks: REQUIRED_TASKS,

        taskStatus,

        payouts: payoutsResult.data || [],

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

            adsPer24Hours: 12,

            requiredAds: REQUIRED_ADS,

            requiredTasks: REQUIRED_TASKS,

            adsgramBlockId: ADSGRAM_BLOCK_ID,

            youtubeTasksComingSoon: 4
        }
    };
}

// ==========================================
// HEALTH CHECK
// ==========================================

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

// ==========================================
// CREATE / SYNC USER
// ==========================================

app.post(
    '/sync',
    authenticateTelegram,
    async (req, res) => {
        try {
            const tg = req.telegramUser;

            const startParam = String(
                req.body?.startParam ||
                tg.start_param ||
                ''
            );

            let referrerId = null;

            if (/^ref_\d{1,20}$/.test(startParam)) {
                referrerId = startParam.slice(4);
            }

            // Users cannot refer themselves.
            if (referrerId === tg.id) {
                referrerId = null;
            }

            const { error } = await db.rpc(
                'trial_sync_user',
                {
                    p_telegram_id: tg.id,

                    p_first_name: tg.first_name,

                    p_username: tg.username || null,

                    p_photo_url: tg.photo_url || null,

                    p_referrer_id: referrerId,

                    p_joining_bonus: JOINING_BONUS,

                    p_referral_reward: REFERRAL_REWARD
                }
            );

            if (error) {
                console.error(
                    'Account sync error:',
                    error.message
                );

                return sendError(
                    res,
                    500,
                    'Account setup failed. Check the new Supabase SQL.'
                );
            }

            const account = await getAccount(tg);

            return res.json({
                success: true,
                ...account
            });

        } catch (error) {
            console.error(
                'Sync error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Could not initialize account.'
            );
        }
    }
);

// ==========================================
// LOAD ACCOUNT
// ==========================================

app.post(
    '/account',
    authenticateTelegram,
    async (req, res) => {
        try {
            const account = await getAccount(
                req.telegramUser
            );

            return res.json({
                success: true,
                ...account
            });

        } catch (error) {
            console.error(
                'Account error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Could not load account.'
            );
        }
    }
);

// ==========================================
// ADSGRAM CLAIM
// ==========================================

// IMPORTANT:
// This endpoint must NOT be used for real-money rewards
// until genuine ad completion is independently verified
// using a trusted provider-side verification mechanism.
//
// A browser/client success response alone is not sufficient
// proof that an advertisement was completed.

app.post(
    '/adsgram/claim',
    authenticateTelegram,
    async (req, res) => {
        return sendError(
            res,
            503,
            'Ad rewards are temporarily disabled until server-side ad verification is configured.'
        );
    }
);

// ==========================================
// SUBMIT TELEGRAM TASK
// ==========================================

app.post(
    '/tasks/submit',
    authenticateTelegram,
    async (req, res) => {
        try {
            const taskKey = String(
                req.body?.taskKey || ''
            );

            const allowedTasks = [
                'telegram_earn',
                'telegram_payout'
            ];

            if (!allowedTasks.includes(taskKey)) {
                return sendError(
                    res,
                    400,
                    'This task is not available yet.'
                );
            }

            const { data, error } = await db.rpc(
                'trial_submit_task',
                {
                    p_telegram_id:
                        req.telegramUser.id,

                    p_task_key: taskKey
                }
            );

            if (error) {
                console.error(
                    'Task submission error:',
                    error.message
                );

                return sendError(
                    res,
                    400,
                    'Task already submitted or database setup is incomplete.'
                );
            }

            return res.json({
                success: true,
                result: data,
                message:
                    'Submitted for admin verification.'
            });

        } catch (error) {
            console.error(
                'Task error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Could not submit task.'
            );
        }
    }
);

// ==========================================
// ADMIN APPROVES / REJECTS TELEGRAM TASK
// ==========================================

// Verify channel membership yourself before approving.
// Never expose ADMIN_SECRET in the frontend.

app.post(
    '/admin/task/review',
    authenticateAdmin,
    async (req, res) => {
        try {
            const telegramId = String(
                req.body?.telegramId || ''
            );

            const taskKey = String(
                req.body?.taskKey || ''
            );

            const decision = String(
                req.body?.decision || ''
            );

            if (
                !/^\d{1,20}$/.test(telegramId) ||
                ![
                    'telegram_earn',
                    'telegram_payout'
                ].includes(taskKey) ||
                !['approve', 'reject'].includes(decision)
            ) {
                return sendError(
                    res,
                    400,
                    'Invalid review data.'
                );
            }

            const { data, error } = await db.rpc(
                'trial_review_task',
                {
                    p_telegram_id: telegramId,

                    p_task_key: taskKey,

                    p_decision: decision,

                    p_reward: TASK_REWARD
                }
            );

            if (error) {
                console.error(
                    'Task review error:',
                    error.message
                );

                return sendError(
                    res,
                    400,
                    'Could not review task.'
                );
            }

            return res.json({
                success: true,
                result: data
            });

        } catch (error) {
            console.error(
                'Admin review error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Task review failed.'
            );
        }
    }
);

// ==========================================
// PAYOUT HISTORY
// ==========================================

app.post(
    '/payouts',
    authenticateTelegram,
    async (req, res) => {
        try {
            const { data, error } = await db
                .from('trial_payouts')
                .select('*')
                .eq(
                    'telegram_id',
                    req.telegramUser.id
                )
                .order('created_at', {
                    ascending: false
                })
                .limit(50);

            if (error) {
                throw error;
            }

            return res.json({
                success: true,
                payouts: data || []
            });

        } catch (error) {
            console.error(
                'Payout history error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Could not load payout history.'
            );
        }
    }
);

// ==========================================
// AUTOMATIC USDT PAYOUT
// ==========================================

// Keep PAYOUT_MODE=disabled until the complete
// payout flow has been audited and tested.
//
// Do not put the private key in frontend code.
// Use only a dedicated, funded payout wallet.

async function sendUsdt(walletAddress, amount) {
    if (PAYOUT_MODE !== 'automatic') {
        throw new Error(
            'Automatic payout is disabled.'
        );
    }

    if (
        !PAYOUT_RPC_URL ||
        !PAYOUT_PRIVATE_KEY ||
        !PAYOUT_CONTRACT_ADDRESS
    ) {
        throw new Error(
            'Payout environment variables are incomplete.'
        );
    }

    if (
        !ethers.isAddress(walletAddress) ||
        !ethers.isAddress(PAYOUT_CONTRACT_ADDRESS)
    ) {
        throw new Error('Invalid wallet or token address.');
    }

    const provider = new ethers.JsonRpcProvider(
        PAYOUT_RPC_URL,
        PAYOUT_CHAIN_ID
    );

    const wallet = new ethers.Wallet(
        PAYOUT_PRIVATE_KEY,
        provider
    );

    const token = new ethers.Contract(
        PAYOUT_CONTRACT_ADDRESS,
        [
            'function decimals() view returns (uint8)',
            'function transfer(address,uint256) returns (bool)'
        ],
        wallet
    );

    const decimals = Number(
        await token.decimals()
    );

    const parsedAmount = ethers.parseUnits(
        String(amount),
        decimals
    );

    // Check the connected network.
    const network = await provider.getNetwork();

    if (Number(network.chainId) !== PAYOUT_CHAIN_ID) {
        throw new Error(
            'Payout RPC is connected to the wrong network.'
        );
    }

    const transaction = await token.transfer(
        walletAddress,
        parsedAmount
    );

    return {
        hash: transaction.hash,

        wait: () => transaction.wait(1)
    };
}

// ==========================================
// WITHDRAWAL REQUEST
// ==========================================

// SAFETY:
// This endpoint deliberately keeps automatic payout disabled.
// A safe live-payment implementation needs idempotent payout
// state transitions, transaction reconciliation and protection
// against duplicate payments before enabling transfers.

app.post(
    '/payout',
    authenticateTelegram,
    async (req, res) => {
        try {
            if (PAYOUT_MODE !== 'automatic') {
                return sendError(
                    res,
                    503,
                    'Automatic payouts are not enabled yet.'
                );
            }

            // Do not broadcast transfers until the payout
            // reservation, transaction tracking, and refund
            // process have been independently audited.

            return sendError(
                res,
                503,
                'Payout processing is not activated. The payment workflow must be audited before live transfers.'
            );

        } catch (error) {
            console.error(
                'Payout error:',
                error.message
            );

            return sendError(
                res,
                500,
                'Could not process withdrawal.'
            );
        }
    }
);

// ==========================================
// UNKNOWN API ROUTE
// ==========================================

app.use((req, res) => {
    return sendError(
        res,
        404,
        'API endpoint not found.'
    );
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(
        `NX USDT API listening on port ${PORT}`
    );
});
