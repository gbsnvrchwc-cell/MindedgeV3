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
app.post('/api/create-checkout', checkoutLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Payments not configured' });
  }
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'MindEdge — Lifetime Access',
            description: 'AI-powered trading psychology platform. One-time payment, lifetime access.',
          },
          unit_amount: 1499,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
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
  const { session_id } = req.query;
  if (!session_id) return res.redirect('/paywall');
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') return res.redirect('/paywall?error=not_paid');

    const token = issueToken({
      access: true,
      tier: 'pro',
      email: session.customer_details?.email || 'user',
      paid_at: Date.now(),
      stripe_session: session.id,
    });

    setAccessCookie(res, token);
    res.redirect('/app');
  } catch (err) {
    console.error('Verification error:', err.message);
    res.redirect('/paywall?error=verification_failed');
  }
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
app.post('/api/analyze-trade', requireAccessAPI, aiLimiter, chartLimiter, async (req, res) => {
  const { entryTime, exitTime, entryPrice, exitPrice, direction, notes } = req.body;

  if (!entryTime || !exitTime) {
    return res.status(400).json({ error: 'Entry and exit time required' });
  }

  try {
    // Fetch SPX data for 1m, 5m, 15m timeframes
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
        open: quotes.open[i]?.toFixed(2),
        high: quotes.high[i]?.toFixed(2),
        low: quotes.low[i]?.toFixed(2),
        close: quotes.close[i]?.toFixed(2),
        volume: quotes.volume[i],
      })).filter(b => b.close !== null && b.close !== undefined);
    };

    const [chart1m, chart5m, chart15m] = await Promise.all([
      fetchChart('1m', '1d'),
      fetchChart('5m', '5d'),
      fetchChart('15m', '1mo'),
    ]);

    // Find bars around entry and exit
    const entryTs = new Date(entryTime).getTime();
    const exitTs = new Date(exitTime).getTime();

    const getBarsAround = (chart, targetTs, windowMs) => {
      return chart.filter(b => {
        const ts = new Date(b.time).getTime();
        return ts >= targetTs - windowMs && ts <= exitTs + windowMs;
      });
    };

    const context1m  = getBarsAround(chart1m,  entryTs, 30 * 60 * 1000);   // ±30 min
    const context5m  = getBarsAround(chart5m,  entryTs, 2 * 60 * 60 * 1000); // ±2 hr
    const context15m = getBarsAround(chart15m, entryTs, 4 * 60 * 60 * 1000); // ±4 hr

    // Build analysis prompt
    const prompt = `You are an elite SPX scalping analyst. Analyze this trade using the provided multi-timeframe chart data.

TRADE DETAILS:
- Direction: ${direction || 'Long'}
- Entry Time: ${entryTime}
- Exit Time: ${exitTime}
- Entry Price: ${entryPrice || 'Not provided'}
- Exit Price: ${exitPrice || 'Not provided'}
- P&L: ${entryPrice && exitPrice ? ((parseFloat(exitPrice) - parseFloat(entryPrice)) * (direction === 'Short' ? -1 : 1)).toFixed(2) + ' points' : 'Not calculated'}
- Trader Notes: ${notes || 'None'}

15-MINUTE CHART (Context/Trend):
${JSON.stringify(context15m.slice(-20), null, 1)}

5-MINUTE CHART (Setup):
${JSON.stringify(context5m.slice(-24), null, 1)}

1-MINUTE CHART (Execution):
${JSON.stringify(context1m, null, 1)}

Provide a structured analysis covering:
1. **Market Context (15m)**: What was the higher timeframe trend and structure at the time of the trade? Key levels visible.
2. **Setup Quality (5m)**: Was there a valid setup on the 5-minute? What did price action show before entry?
3. **Entry Execution (1m)**: Was the entry timing optimal on the 1-minute? Was there a cleaner entry point?
4. **Exit Analysis**: Was the exit too early, too late, or well-timed?
5. **What Worked**: Specific reasons the trade worked (if profitable).
6. **What Could Be Improved**: Specific, actionable improvements for next time.
7. **Scalping Grade**: Rate this trade A/B/C/D on execution quality with one sentence explanation.

Be specific about price levels, candlestick patterns, and market structure. Reference exact times and prices from the data.`;

    // Call Claude for analysis
    const aiResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!aiResponse.ok) throw new Error('AI analysis failed');
    const aiData = await aiResponse.json();
    const analysis = aiData.content?.[0]?.text || 'Analysis unavailable';

    res.json({
      analysis,
      chartSummary: {
        bars1m: context1m.length,
        bars5m: context5m.length,
        bars15m: context15m.length,
        currentPrice: chart1m[chart1m.length - 1]?.close,
      }
    });

  } catch (err) {
    console.error('Trade analysis error:', err.message);
    res.status(500).json({ error: 'Could not fetch chart data: ' + err.message });
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
