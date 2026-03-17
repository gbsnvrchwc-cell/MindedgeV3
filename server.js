const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1); // Required for Railway proxy
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mindedge-dev-secret-change-in-production';
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;
const ADMIN_CODE = process.env.ADMIN_CODE || 'MINDEDGE-ADMIN';

// ── SECURITY HEADERS ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://js.stripe.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://fonts.googleapis.com', 'data:'],
      connectSrc: ["'self'", 'https://api.anthropic.com', 'https://checkout.stripe.com'],
      frameSrc: ["'self'", 'https://js.stripe.com', 'https://checkout.stripe.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      formAction: ["'self'", 'https://checkout.stripe.com'],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — only allow your own domain ────────────────────────────
const allowedOrigins = [
  DOMAIN,
  'http://localhost:3000',
  'https://mindedge.app',
  /\.railway\.app$/,
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    const allowed = allowedOrigins.some(o =>
      typeof o === 'string' ? o === origin : o.test(origin)
    );
    cb(allowed ? null : new Error('Not allowed by CORS'), allowed);
  },
  credentials: true,
}));

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

// ── RATE LIMITERS ────────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30,                   // 30 AI calls per hour per IP
  message: { error: 'AI rate limit reached. Please wait before making more requests.' },
});

const checkoutLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many checkout attempts.' },
});

const chartLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,                   // 10 chart lookups per minute
  message: { error: 'Chart request limit reached. Please wait.' },
});

app.use(generalLimiter);

// ── AUTH HELPERS ─────────────────────────────────────────────────
function issueToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '3650d' });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function setAccessCookie(res, token) {
  res.cookie('mindedge_access', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 3650,
  });
}

function requireAccess(req, res, next) {
  const token = req.cookies.mindedge_access;
  if (!token) return res.redirect('/paywall');
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    res.clearCookie('mindedge_access');
    res.redirect('/paywall');
  }
}

function requireAccessAPI(req, res, next) {
  const token = req.cookies.mindedge_access;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}

// ── STATIC ───────────────────────────────────────────────────────
app.use('/paywall-assets', express.static(path.join(__dirname, 'paywall')));

// ── ROUTES ───────────────────────────────────────────────────────
app.get('/', (req, res) => {
  try {
    if (req.cookies.mindedge_access) {
      verifyToken(req.cookies.mindedge_access);
      return res.redirect('/app');
    }
  } catch { res.clearCookie('mindedge_access'); }
  res.redirect('/paywall');
});

app.get('/paywall', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'paywall', 'index.html'));
});

app.get('/app', requireAccess, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '3.0.0', time: new Date().toISOString() });
});

// Check if current user is authenticated (for frontend)
app.get('/api/auth-status', (req, res) => {
  const token = req.cookies.mindedge_access;
  if (!token) return res.json({ authenticated: false });
  try {
    const user = verifyToken(token);
    res.json({ authenticated: true, tier: user.tier || 'pro', email: user.email });
  } catch {
    res.json({ authenticated: false });
  }
});

// ── FREE ACCESS CODE (for analyst community) ─────────────────────
// You can give community members a code to get free access
app.post('/api/redeem-code', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });

  const validCodes = (process.env.ACCESS_CODES || '').split(',').map(c => c.trim().toUpperCase());
  const isAdmin = code.toUpperCase() === ADMIN_CODE;
  const isValid = isAdmin || validCodes.includes(code.toUpperCase());

  if (!isValid) return res.status(400).json({ error: 'Invalid access code' });

  const token = issueToken({
    access: true,
    tier: isAdmin ? 'admin' : 'community',
    code: code.toUpperCase(),
    granted_at: Date.now(),
  });

  setAccessCookie(res, token);
  res.json({ success: true, tier: isAdmin ? 'admin' : 'community' });
});

// ── STRIPE CHECKOUT ──────────────────────────────────────────────
const PRODUCTS = {
  app: {
    name: 'MindEdge Platform — Lifetime Access',
    description: 'AI-powered trading psychology platform. One-time payment, lifetime access.',
    amount: 3499,
    tier: 'pro',
    includesGuide: false,
  },
  guide: {
    name: 'SPX Scalping Framework — PDF Guide',
    description: '8-page professional SPX scalping guide: 9/21 EMA, Fibonacci OTE, BOS/ChoCh, VRVP, GEX.',
    amount: 1999,
    tier: 'guide',
    includesGuide: true,
  },
  bundle: {
    name: 'MindEdge Complete Bundle — Platform + Guide',
    description: 'MindEdge platform lifetime access + SPX Scalping Framework PDF. Best value.',
    amount: 4499,
    tier: 'pro',
    includesGuide: true,
  },
};

app.post('/api/create-checkout', checkoutLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Payments not configured' });
  }
  const product = PRODUCTS[req.body.product] || PRODUCTS.app;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: product.name,
            description: product.description,
          },
          unit_amount: product.amount,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}&product=${req.body.product || 'app'}`,
      cancel_url: `${DOMAIN}/paywall`,
      allow_promotion_codes: true,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

app.get('/payment-success', async (req, res) => {
  const { session_id, product } = req.query;
  if (!session_id) return res.redirect('/paywall');
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') return res.redirect('/paywall?error=not_paid');

    const productInfo = PRODUCTS[product] || PRODUCTS.app;

    // Guide-only purchase: send PDF directly, no app access cookie
    if (product === 'guide') {
      const token = issueToken({
        access: false,
        tier: 'guide',
        email: session.customer_details?.email || 'user',
        paid_at: Date.now(),
        stripe_session: session.id,
      });
      // Redirect to guide download page
      return res.redirect('/download-guide?token=' + token);
    }

    // App or bundle: set access cookie
    const token = issueToken({
      access: true,
      tier: productInfo.tier,
      email: session.customer_details?.email || 'user',
      paid_at: Date.now(),
      stripe_session: session.id,
      includesGuide: productInfo.includesGuide,
    });

    setAccessCookie(res, token);

    // Bundle: redirect to app with guide download prompt
    if (product === 'bundle') return res.redirect('/app?guide=1');
    res.redirect('/app');
  } catch (err) {
    console.error('Verification error:', err.message);
    res.redirect('/paywall?error=verification_failed');
  }
});

// Guide download page
app.get('/download-guide', (req, res) => {
  const { token } = req.query;
  try {
    const payload = verifyToken(token);
    if (payload.tier !== 'guide' && payload.tier !== 'pro' && payload.tier !== 'community' && payload.tier !== 'admin') {
      return res.status(403).send('Access denied');
    }
    // Serve the PDF
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="MindEdge_SPX_Scalping_Framework.pdf"');
    res.sendFile(path.join(__dirname, 'downloads', 'spx_scalping_guide.pdf'));
  } catch {
    res.redirect('/paywall?error=invalid_token');
  }
});

// Guide download for logged-in bundle users
app.get('/api/download-guide', requireAccessAPI, (req, res) => {
  // Allow all authenticated users to download — community, admin, pro, and bundle
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="MindEdge_SPX_Scalping_Framework.pdf"');
  res.sendFile(path.join(__dirname, 'downloads', 'spx_scalping_guide.pdf'));
});

// ── CLAUDE AI PROXY (protected + rate limited) ───────────────────
app.post('/api/chat', requireAccessAPI, aiLimiter, async (req, res) => {
  const { messages, system } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Valid messages array required' });
  }
  if (messages.length > 20) {
    return res.status(400).json({ error: 'Too many messages in conversation' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'AI service not configured' });
  }

  // Sanitize — strip any attempt to leak system prompt
  const cleanMessages = messages.map(m => ({
    role: m.role === 'assistant' ? 'assistant' : 'user',
    content: String(m.content).substring(0, 4000),
  }));

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: system ? String(system).substring(0, 8000) : '',
        messages: cleanMessages,
      }),
    });

    if (!response.ok) {
      const err = await response.json();
      return res.status(response.status).json({ error: err.error?.message || 'AI API error' });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).json({ error: 'AI service unavailable' });
  }
});

// ── TRADE ANALYSIS — fetch SPX chart data ───────────────────────
// ── INDICATOR CALCULATIONS ───────────────────────────────────────

function calcEMA(bars, period) {
  const closes = bars.map(b => parseFloat(b.close)).filter(v => !isNaN(v));
  if (closes.length < period) return [];
  const k = 2 / (period + 1);
  const emas = [closes.slice(0, period).reduce((s, v) => s + v, 0) / period];
  for (let i = period; i < closes.length; i++) {
    emas.push(closes[i] * k + emas[emas.length - 1] * (1 - k));
  }
  // Return last N values aligned to bars
  const offset = closes.length - emas.length;
  return bars.slice(offset).map((b, i) => ({
    time: b.time,
    ema: parseFloat(emas[i].toFixed(2)),
  }));
}

function calcFibLevels(bars) {
  if (bars.length < 2) return null;
  const highs = bars.map(b => parseFloat(b.high));
  const lows  = bars.map(b => parseFloat(b.low));
  const swingHigh = Math.max(...highs);
  const swingLow  = Math.min(...lows);
  const range = swingHigh - swingLow;
  const ratios = [0, 0.236, 0.382, 0.5, 0.618, 0.705, 0.786, 1.0];
  const levels = {};
  ratios.forEach(r => {
    levels['fib_' + (r * 100).toFixed(1)] = parseFloat((swingHigh - range * r).toFixed(2));
  });
  levels.swing_high = parseFloat(swingHigh.toFixed(2));
  levels.swing_low  = parseFloat(swingLow.toFixed(2));
  levels.range      = parseFloat(range.toFixed(2));
  return levels;
}

function detectBOSChoCh(bars) {
  const events = [];
  if (bars.length < 6) return events;
  let lastSwingHigh = null, lastSwingLow = null;
  let trend = 'neutral';

  for (let i = 2; i < bars.length - 2; i++) {
    const h = parseFloat(bars[i].high);
    const l = parseFloat(bars[i].low);
    const isSwingHigh = h > parseFloat(bars[i-1].high) && h > parseFloat(bars[i-2].high) &&
                        h > parseFloat(bars[i+1].high) && h > parseFloat(bars[i+2].high);
    const isSwingLow  = l < parseFloat(bars[i-1].low)  && l < parseFloat(bars[i-2].low)  &&
                        l < parseFloat(bars[i+1].low)   && l < parseFloat(bars[i+2].low);

    if (isSwingHigh) {
      if (lastSwingHigh !== null) {
        if (h > lastSwingHigh.price) {
          events.push({ type: trend === 'bullish' ? 'BOS_up' : 'ChoCh_up', time: bars[i].time, price: h.toFixed(2), label: trend === 'bullish' ? 'BOS (Higher High)' : 'ChoCh (Bullish Reversal)' });
          trend = 'bullish';
        }
      }
      lastSwingHigh = { price: h, time: bars[i].time };
    }
    if (isSwingLow) {
      if (lastSwingLow !== null) {
        if (l < lastSwingLow.price) {
          events.push({ type: trend === 'bearish' ? 'BOS_down' : 'ChoCh_down', time: bars[i].time, price: l.toFixed(2), label: trend === 'bearish' ? 'BOS (Lower Low)' : 'ChoCh (Bearish Reversal)' });
          trend = 'bearish';
        }
      }
      lastSwingLow = { price: l, time: bars[i].time };
    }
  }
  return events.slice(-10);
}

function calcVRVP(bars, buckets = 20) {
  if (!bars.length) return [];
  const allHighs  = bars.map(b => parseFloat(b.high));
  const allLows   = bars.map(b => parseFloat(b.low));
  const priceMin  = Math.min(...allLows);
  const priceMax  = Math.max(...allHighs);
  const bucketSize = (priceMax - priceMin) / buckets;
  const profile    = Array.from({ length: buckets }, (_, i) => ({
    priceLevel: parseFloat((priceMin + i * bucketSize).toFixed(2)),
    volume: 0,
  }));
  bars.forEach(b => {
    const midPrice = (parseFloat(b.high) + parseFloat(b.low)) / 2;
    const idx = Math.min(Math.floor((midPrice - priceMin) / bucketSize), buckets - 1);
    if (idx >= 0) profile[idx].volume += (b.volume || 0);
  });
  const maxVol = Math.max(...profile.map(p => p.volume));
  profile.forEach(p => { p.relVolume = maxVol > 0 ? parseFloat((p.volume / maxVol * 100).toFixed(1)) : 0; });
  // Find POC (Point of Control) — highest volume node
  const poc = profile.reduce((a, b) => b.volume > a.volume ? b : a);
  // Find Value Area (70% of total volume around POC)
  const totalVol = profile.reduce((s, p) => s + p.volume, 0);
  const targetVol = totalVol * 0.70;
  let accumulated = poc.volume, vaHigh = poc.priceLevel, vaLow = poc.priceLevel;
  let hi = profile.findIndex(p => p.priceLevel === poc.priceLevel);
  let lo = hi, hiPtr = hi + 1, loPtr = hi - 1;
  while (accumulated < targetVol) {
    const nextHi = hiPtr < buckets ? profile[hiPtr].volume : 0;
    const nextLo = loPtr >= 0     ? profile[loPtr].volume : 0;
    if (nextHi >= nextLo && hiPtr < buckets) { accumulated += nextHi; vaHigh = profile[hiPtr].priceLevel; hiPtr++; }
    else if (loPtr >= 0) { accumulated += nextLo; vaLow = profile[loPtr].priceLevel; loPtr--; }
    else break;
  }
  return {
    poc:   parseFloat(poc.priceLevel.toFixed(2)),
    vaHigh: parseFloat(vaHigh.toFixed(2)),
    vaLow:  parseFloat(vaLow.toFixed(2)),
    profile: profile.filter(p => p.relVolume > 5).map(p => ({ price: p.priceLevel, relVol: p.relVolume })),
  };
}

function calcSVP(bars) {
  // Session Volume Profile — same as VRVP but scoped to today's RTH session only
  const today = new Date().toISOString().split('T')[0];
  const sessionBars = bars.filter(b => b.time.startsWith(today));
  if (sessionBars.length < 3) return null;
  return calcVRVP(sessionBars, 15);
}

function emaAtTime(emaArr, targetTime) {
  if (!emaArr.length) return null;
  const ts = new Date(targetTime).getTime();
  let closest = emaArr[0];
  for (const e of emaArr) {
    if (Math.abs(new Date(e.time).getTime() - ts) < Math.abs(new Date(closest.time).getTime() - ts)) {
      closest = e;
    }
  }
  return closest.ema;
}

// ── TRADE ANALYSIS ENDPOINT ──────────────────────────────────────
app.post('/api/analyze-trade', requireAccessAPI, aiLimiter, chartLimiter, async (req, res) => {
  const { entryTime, exitTime, entryPrice, exitPrice, direction, notes, gexLevels, sessionWindow, preTrade5Checks } = req.body;

  if (!entryTime || !exitTime) {
    return res.status(400).json({ error: 'Entry and exit time required' });
  }

  try {
    const fetchChart = async (interval, range) => {
      const url = `https://query1.finance.yahoo.com/v8/finance/chart/%5EGSPC?interval=${interval}&range=${range}&includePrePost=false`;
      const r = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'application/json',
        },
      });
      if (!r.ok) throw new Error(`Yahoo Finance error: ${r.status}`);
      const data = await r.json();
      const result = data.chart.result[0];
      const timestamps = result.timestamp;
      const quotes = result.indicators.quote[0];
      return timestamps.map((ts, i) => ({
        time: new Date(ts * 1000).toISOString(),
        open:   quotes.open[i]   != null ? parseFloat(quotes.open[i].toFixed(2))   : null,
        high:   quotes.high[i]   != null ? parseFloat(quotes.high[i].toFixed(2))   : null,
        low:    quotes.low[i]    != null ? parseFloat(quotes.low[i].toFixed(2))    : null,
        close:  quotes.close[i]  != null ? parseFloat(quotes.close[i].toFixed(2))  : null,
        volume: quotes.volume[i] || 0,
      })).filter(b => b.close !== null);
    };

    const [chart1m, chart5m, chart15m] = await Promise.all([
      fetchChart('1m', '1d'),
      fetchChart('5m', '5d'),
      fetchChart('15m', '1mo'),
    ]);

    const entryTs = new Date(entryTime).getTime();
    const exitTs  = new Date(exitTime).getTime();

    const getBarsAround = (chart, windowMs) =>
      chart.filter(b => {
        const ts = new Date(b.time).getTime();
        return ts >= entryTs - windowMs && ts <= exitTs + windowMs;
      });

    const context1m  = getBarsAround(chart1m,  45 * 60 * 1000);
    const context5m  = getBarsAround(chart5m,  3  * 60 * 60 * 1000);
    const context15m = getBarsAround(chart15m, 6  * 60 * 60 * 1000);

    // ── CALCULATE INDICATORS ──────────────────────────────────────

    // EMA 9 & 21 on each timeframe
    const ema9_1m   = calcEMA(chart1m,  9);
    const ema21_1m  = calcEMA(chart1m,  21);
    const ema9_5m   = calcEMA(chart5m,  9);
    const ema21_5m  = calcEMA(chart5m,  21);
    const ema9_15m  = calcEMA(chart15m, 9);
    const ema21_15m = calcEMA(chart15m, 21);

    // EMAs at entry time
    const emaAtEntry = {
      '1m':  { ema9: emaAtTime(ema9_1m, entryTime),   ema21: emaAtTime(ema21_1m, entryTime)  },
      '5m':  { ema9: emaAtTime(ema9_5m, entryTime),   ema21: emaAtTime(ema21_5m, entryTime)  },
      '15m': { ema9: emaAtTime(ema9_15m, entryTime),  ema21: emaAtTime(ema21_15m, entryTime) },
    };

    // EMA crossovers near entry (last 10 bars of each TF)
    const findCrossovers = (ema9arr, ema21arr) => {
      const crossovers = [];
      const len = Math.min(ema9arr.length, ema21arr.length);
      for (let i = Math.max(0, len - 15); i < len - 1; i++) {
        const curr9  = ema9arr[i].ema,   curr21  = ema21arr[i].ema;
        const next9  = ema9arr[i+1].ema, next21  = ema21arr[i+1].ema;
        if (curr9 < curr21 && next9 >= next21) crossovers.push({ time: ema9arr[i+1].time, type: 'Bullish crossover (9 crossed above 21)', ema9: next9, ema21: next21 });
        if (curr9 > curr21 && next9 <= next21) crossovers.push({ time: ema9arr[i+1].time, type: 'Bearish crossover (9 crossed below 21)', ema9: next9, ema21: next21 });
      }
      return crossovers;
    };

    const crossovers = {
      '1m':  findCrossovers(ema9_1m,  ema21_1m),
      '5m':  findCrossovers(ema9_5m,  ema21_5m),
      '15m': findCrossovers(ema9_15m, ema21_15m),
    };

    // Fibonacci levels from each context window
    const fib1m  = calcFibLevels(context1m);
    const fib5m  = calcFibLevels(context5m);
    const fib15m = calcFibLevels(context15m);

    // BOS / ChoCh on each timeframe
    const structure1m  = detectBOSChoCh(context1m);
    const structure5m  = detectBOSChoCh(context5m);
    const structure15m = detectBOSChoCh(context15m);

    // VRVP (Visible Range Volume Profile) — full context window
    const vrvp5m  = calcVRVP(context5m);
    const vrvp15m = calcVRVP(context15m);

    // SVP (Session Volume Profile) — today's session only
    const svp = calcSVP(chart1m);

    // EMA slope at entry (bullish/bearish/flat)
    const emaSlope = (emaArr, lookback = 3) => {
      if (emaArr.length < lookback + 1) return 'insufficient data';
      const recent = emaArr.slice(-lookback);
      const diff = recent[recent.length-1].ema - recent[0].ema;
      if (diff > 0.5) return 'rising strongly';
      if (diff > 0.1) return 'rising';
      if (diff < -0.5) return 'falling strongly';
      if (diff < -0.1) return 'falling';
      return 'flat';
    };

    const ep = parseFloat(entryPrice) || null;
    const xp = parseFloat(exitPrice)  || null;
    const pnl = ep && xp ? ((xp - ep) * (direction === 'Short' ? -1 : 1)).toFixed(2) : 'not provided';

    // ── BUILD COMPREHENSIVE PROMPT ────────────────────────────────
    // Format times for display - keep original ISO for processing but show readable format
    const formatTime = (isoStr) => {
      try {
        return new Date(isoStr).toLocaleString('en-US', {
          month: 'short', day: 'numeric', year: 'numeric',
          hour: 'numeric', minute: '2-digit', second: '2-digit',
          hour12: true, timeZoneName: 'short'
        });
      } catch { return isoStr; }
    };
    const entryDisplay = formatTime(entryTime);
    const exitDisplay  = formatTime(exitTime);

    // ── SESSION WINDOW CHECK ─────────────────────────────────────
    const entryDate = new Date(entryTime);
    const entryHour = entryDate.getUTCHours(); // will be ET offset by user's input
    const entryMin  = entryDate.getUTCMinutes();
    const entryTotalMins = entryHour * 60 + entryMin;
    // Convert UTC to ET (UTC-4 EDT or UTC-5 EST) — approximate
    const etOffset = 4; // assume EDT
    const etHour = ((entryHour - etOffset + 24) % 24);
    const etMins = etHour * 60 + entryMin;
    let sessionWindowStatus = 'UNKNOWN';
    if (etMins >= 9*60+30 && etMins <= 10*60+30) sessionWindowStatus = 'PRIME (9:30-10:30am ET) — APPROVED';
    else if (etMins > 10*60+30 && etMins <= 11*60+30) sessionWindowStatus = 'MID-MORNING (10:30-11:30am ET) — SELECTIVE';
    else if (etMins > 11*60+30 && etMins < 15*60) sessionWindowStatus = 'LUNCH HOURS — AVOID (low volume, high noise)';
    else if (etMins >= 15*60 && etMins <= 16*60) sessionWindowStatus = 'POWER HOUR (3:00-4:00pm ET) — APPROVED';
    else if (etMins < 9*60+30) sessionWindowStatus = 'PRE-MARKET — outside approved window';
    else sessionWindowStatus = 'AFTER-HOURS — outside approved window';

    const prompt = `You are an elite SPX scalper and technical analyst. Analyze this trade using the trader's exact strategy: 9/21 EMA, Fibonacci levels, BOS/ChoCh market structure, VRVP, SVP, and GEX levels. All indicator values have been pre-calculated from live Yahoo Finance data and are provided below.

═══════════════════════════════
TRADE DETAILS
═══════════════════════════════
Direction: ${direction || 'Long'}
Entry Time: ${entryDisplay}
Exit Time: ${exitDisplay}
Session Window: ${sessionWindowStatus}
Pre-Trade 5 Checks Completed: ${preTrade5Checks || 'Not confirmed by trader'}
GEX Provided: ${gexLevels ? 'YES' : 'NO — MANDATORY per v2.0 rules'}
Entry Price: ${ep || 'not provided'}
Exit Price: ${xp || 'not provided'}
P&L: ${pnl} points
Trader Notes: ${notes || 'none'}

═══════════════════════════════
9 / 21 EMA — AT ENTRY MOMENT
═══════════════════════════════
1-min:  EMA9 = ${emaAtEntry['1m'].ema9}  |  EMA21 = ${emaAtEntry['1m'].ema21}  |  ${emaAtEntry['1m'].ema9 > emaAtEntry['1m'].ema21 ? 'BULLISH (9 above 21)' : 'BEARISH (9 below 21)'}
5-min:  EMA9 = ${emaAtEntry['5m'].ema9}  |  EMA21 = ${emaAtEntry['5m'].ema21}  |  ${emaAtEntry['5m'].ema9 > emaAtEntry['5m'].ema21 ? 'BULLISH (9 above 21)' : 'BEARISH (9 below 21)'}
15-min: EMA9 = ${emaAtEntry['15m'].ema9}  |  EMA21 = ${emaAtEntry['15m'].ema21}  |  ${emaAtEntry['15m'].ema9 > emaAtEntry['15m'].ema21 ? 'BULLISH (9 above 21)' : 'BEARISH (9 below 21)'}

EMA Slopes (15m): EMA9 ${emaSlope(ema9_15m)} | EMA21 ${emaSlope(ema21_15m)}
EMA Slopes (5m):  EMA9 ${emaSlope(ema9_5m)}  | EMA21 ${emaSlope(ema21_5m)}

Recent EMA Crossovers (1m): ${crossovers['1m'].length ? JSON.stringify(crossovers['1m']) : 'none in window'}
Recent EMA Crossovers (5m): ${crossovers['5m'].length ? JSON.stringify(crossovers['5m']) : 'none in window'}
Recent EMA Crossovers (15m): ${crossovers['15m'].length ? JSON.stringify(crossovers['15m']) : 'none in window'}

═══════════════════════════════
FIBONACCI LEVELS (ChartPrime)
═══════════════════════════════
15-min range (${fib15m?.swing_low} → ${fib15m?.swing_high}, range: ${fib15m?.range} pts):
  0%   = ${fib15m?.fib_0}  (swing high)
  23.6% = ${fib15m?.['fib_23.6']}
  38.2% = ${fib15m?.['fib_38.2']}
  50%   = ${fib15m?.fib_50}
  61.8% = ${fib15m?.['fib_61.8']}  ← Golden ratio
  70.5% = ${fib15m?.['fib_70.5']}  ← ChartPrime OTE zone start
  78.6% = ${fib15m?.['fib_78.6']}  ← ChartPrime OTE zone end
  100%  = ${fib15m?.fib_100} (swing low)

5-min range (${fib5m?.swing_low} → ${fib5m?.swing_high}):
  38.2% = ${fib5m?.['fib_38.2']}  |  50% = ${fib5m?.fib_50}  |  61.8% = ${fib5m?.['fib_61.8']}  |  78.6% = ${fib5m?.['fib_78.6']}

Entry price vs key fib levels:
${ep ? `  Entry (${ep}) is ${ep > (fib5m?.fib_50||0) ? 'ABOVE' : 'BELOW'} 5m 50% fib (${fib5m?.fib_50})` : '  Entry price not provided'}
${ep ? `  Entry (${ep}) is ${ep > (fib15m?.['fib_61.8']||0) ? 'ABOVE' : 'BELOW'} 15m 61.8% fib (${fib15m?.['fib_61.8']})` : ''}

═══════════════════════════════
BOS / ChoCh — MARKET STRUCTURE
═══════════════════════════════
15-min structure events (most recent):
${structure15m.length ? structure15m.map(e => '  ' + e.label + ' at ' + e.price + ' (' + e.time + ')').join('\n') : '  No clear BOS/ChoCh detected in window'}
') : '  No clear BOS/ChoCh detected in window'}

5-min structure events:
${structure5m.length ? structure5m.map(e => '  ' + e.label + ' at ' + e.price + ' (' + e.time + ')').join('\n') : '  No clear BOS/ChoCh detected in window'}
') : '  No clear BOS/ChoCh detected in window'}

1-min structure events (execution):
${structure1m.length ? structure1m.map(e => '  ' + e.label + ' at ' + e.price + ' (' + e.time + ')').join('\n') : '  No clear BOS/ChoCh detected in window'}
') : '  No clear BOS/ChoCh detected in window'}

═══════════════════════════════
VRVP — VISIBLE RANGE VOLUME PROFILE
═══════════════════════════════
15-min VRVP:
  POC (Point of Control): ${vrvp15m?.poc}
  Value Area High (VAH):  ${vrvp15m?.vaHigh}
  Value Area Low (VAL):   ${vrvp15m?.vaLow}
  High volume nodes: ${vrvp15m?.profile?.slice().sort((a,b)=>b.relVol-a.relVol).slice(0,5).map(p=>p.price + ' (' + p.relVol + '%)').join(', ')}

5-min VRVP:
  POC: ${vrvp5m?.poc}  |  VAH: ${vrvp5m?.vaHigh}  |  VAL: ${vrvp5m?.vaLow}

${ep ? `Entry (${ep}) vs VRVP 15m: ${ep > (vrvp15m?.vaHigh||0) ? 'ABOVE value area — premium' : ep < (vrvp15m?.vaLow||0) ? 'BELOW value area — discount' : 'INSIDE value area'}` : ''}
${ep ? `Entry vs POC: ${ep > (vrvp15m?.poc||0) ? 'above POC (+' + (ep - vrvp15m?.poc).toFixed(2) + ')' : 'below POC (' + (ep - vrvp15m?.poc).toFixed(2) + ')'}` : ''}

═══════════════════════════════
SVP — SESSION VOLUME PROFILE
═══════════════════════════════
${svp ? `Session POC: ${svp.poc}  |  Session VAH: ${svp.vaHigh}  |  Session VAL: ${svp.vaLow}
  Session high volume nodes: ${svp.profile?.slice().sort((a,b)=>b.relVol-a.relVol).slice(0,4).map(p=>p.price + ' (' + p.relVol + '%)').join(', ')}` : 'Session data unavailable for this timeframe'}

═══════════════════════════════
GEX LEVELS (Gamma Exposure — trader-provided)
═══════════════════════════════
${gexLevels || 'Not provided by trader — GEX levels must be sourced from SpotGamma, Squeeze Metrics, or similar at time of trade'}

═══════════════════════════════
RAW PRICE ACTION CONTEXT
═══════════════════════════════
15m bars (last 12 before entry):
${JSON.stringify(context15m.slice(-12).map(b=>({t:b.time.slice(11,16),o:b.open,h:b.high,l:b.low,c:b.close,v:Math.round((b.volume||0)/1000)+'k'})), null, 1)}

5m bars (around trade):
${JSON.stringify(context5m.slice(-16).map(b=>({t:b.time.slice(11,16),o:b.open,h:b.high,l:b.low,c:b.close})), null, 1)}

1m bars (execution window):
${JSON.stringify(context1m.map(b=>({t:b.time.slice(11,16),o:b.open,h:b.high,l:b.low,c:b.close})), null, 1)}

═══════════════════════════════
V2.0 ANALYSIS REQUIRED
═══════════════════════════════
Using ALL calculated indicator data above, provide a structured professional trade review applying the v2.0 ruleset:

0. SESSION WINDOW: Was this trade taken during an approved session window (9:30-10:30am or 3:00-4:00pm ET)? Session status: ${sessionWindowStatus}. If outside approved windows, flag this as a rule violation immediately.

1. EMA ALIGNMENT (v2.0): Were the 9/21 EMAs aligned across all three timeframes? Was there a 1-minute vs 5-minute EMA conflict? Per v2.0 rules, a 1m bearish EMA when 5m is bullish requires 50% size reduction or skip. Did the trader violate this rule?

2. FIBONACCI ANALYSIS: Was the entry in the OTE zone (70.5-78.6%) or Golden Pocket (61.8-65%)? Was it a premium or discount entry? The textbook entry per v2.0 is inside the OTE zone — how far was this entry from that ideal?

3. MARKET STRUCTURE (BOS/ChoCh): What was the structural context on 15m and 5m? Did the 1-minute agree with the 30-second trigger? Per v2.0, the 1m must not contradict the 30s trigger.

4. VOLUME PROFILE (VRVP v2.0): Was the entry inside or outside the value area? Note: VRVP should be anchored to session open. Was price near the POC? If entry was outside value area, the POC should have been the target.

5. GEX CONTEXT: ${gexLevels ? 'Analyze the provided GEX levels: ' + gexLevels + '. Were there gamma walls near the entry or blocking the target? Was the trade above or below the HVL? How did GEX affect price behaviour?' : 'RULE VIOLATION: GEX levels were not provided. Per v2.0 rules, GEX is MANDATORY for SPX scalping. Explain what GEX information would have been critical for this trade and where to get it (SpotGamma, Squeeze Metrics).'}

6. SETUP VALIDITY: Based on the 1-minute chart data, did the setup trigger within 3 candles of forming? Per v2.0, a setup that has not triggered within 3 candles on the execution timeframe is INVALIDATED.

7. ENTRY QUALITY SCORE: Rate 0-5 confluences present at entry (session window approved, EMA aligned no conflict, in OTE/Golden Pocket, BOS/ChoCh confirmed, inside value area, GEX clear). State the score and which confluences were present vs missing.

8. EXIT QUALITY (v2.0): Evaluate against specific v2.0 exit criteria: Did EMA9 roll over on 30s? Was there a bearish engulfing on 1m? Did price close below 9 EMA on execution timeframe? Was the exit at +8 points (breakeven rule) or +12 points (50% off rule)?

9. WHAT WORKED / WHAT DIDN'T: Be specific with prices, times, and which v2.0 rules were followed vs violated.

10. IDEAL ENTRY (v2.0): Give the textbook entry price based on OTE zone, EMA support, and VRVP value area. State why this level had better confluence than the actual entry.

11. V2.0 RULE VIOLATIONS: List every v2.0 rule that was violated in this trade. Be direct and specific.

12. SCALPING GRADE: A/B/C/D+ or - with one sentence explaining the primary reason. A = 5/5 confluences, correct session window, no rule violations. B = 3-4 confluences, minor violations. C = 1-2 confluences or major violations. D = fundamental rule violations regardless of outcome.

Be precise. Reference actual calculated values. Grade based on PROCESS not outcome — a profitable trade with rule violations is still a C or D.`;

    const aiResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2500,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!aiResponse.ok) throw new Error('AI analysis failed');
    const aiData = await aiResponse.json();
    const analysis = aiData.content?.[0]?.text || 'Analysis unavailable';

    res.json({
      analysis,
      indicators: {
        emaAtEntry,
        crossovers,
        fib15m, fib5m,
        structure15m, structure5m, structure1m,
        vrvp15m, vrvp5m, svp,
      },
      chartSummary: {
        bars1m:       context1m.length,
        bars5m:       context5m.length,
        bars15m:      context15m.length,
        currentPrice: chart1m[chart1m.length - 1]?.close,
      }
    });

  } catch (err) {
    console.error('Trade analysis error:', err.message);
    res.status(500).json({ error: 'Could not complete analysis: ' + err.message });
  }
});

// ── LOGOUT ───────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  res.clearCookie('mindedge_access');
  res.redirect('/paywall');
});

// ── 404 ──────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── ERROR HANDLER — never leak stack traces ──────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`MindEdge v3 running on port ${PORT}`);
  console.log(`Security: helmet + rate limiting + JWT auth enabled`);
});
