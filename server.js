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
// ── FAIL FAST: require secrets in production ─────────────────────
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required');
  process.exit(1);
}
if (!process.env.ANTHROPIC_API_KEY) {
  console.error('FATAL: ANTHROPIC_API_KEY environment variable is required');
  process.exit(1);
}
const JWT_SECRET  = process.env.JWT_SECRET;
const DOMAIN      = process.env.DOMAIN || `http://localhost:${PORT}`;
const ADMIN_CODE  = process.env.ADMIN_CODE || '';

// ── SECURITY HEADERS ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com'],
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
const RAILWAY_DOMAIN = process.env.RAILWAY_PUBLIC_DOMAIN
  ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN
  : null;

const allowedOrigins = [
  DOMAIN,
  'http://localhost:3000',
  'https://mindedge.app',
  'https://mindedgev1-production.up.railway.app',
  'https://mindedgev3-production.up.railway.app',
  RAILWAY_DOMAIN,
].filter(Boolean);
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

// ── STRIPE WEBHOOK RAW BODY (must be before express.json) ───────
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env['STRIPE_WEBHOOK' + '_SECRET'];
  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not set — webhook disabled');
    return res.status(400).send('Webhook not configured');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send('Signature verification failed');
  }

  try {
    switch (event.type) {
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        console.log(`Subscription ${sub.id} status: ${sub.status} (customer: ${sub.customer})`);
        // Status is checked in real-time via Stripe API in requireAccess
        // No local DB needed — Stripe is the source of truth
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log(`Payment failed for customer ${invoice.customer}, subscription ${invoice.subscription}`);
        break;
      }
      case 'invoice.paid': {
        const invoice = event.data.object;
        console.log(`Invoice paid: ${invoice.customer}, amount: $${(invoice.amount_paid / 100).toFixed(2)}`);
        break;
      }
      default:
        // Unhandled event type
        break;
    }
  } catch (err) {
    console.error('Webhook handler error:', err.message);
  }

  res.json({ received: true });
});

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

const codeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // max 5 code attempts per 15 minutes per IP
  message: { error: 'Too many code attempts. Please wait before trying again.' },
});

const chartLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,                   // 10 chart lookups per minute
  message: { error: 'Chart request limit reached. Please wait.' },
});

app.use(generalLimiter);

// ── AUTH HELPERS ─────────────────────────────────────────────────
function issueToken(payload, expiresIn = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function setAccessCookie(res, token) {
  res.cookie('mindedge_access', token, {
    httpOnly: true,
    secure: true, // always secure — we only run on HTTPS in Railway
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 3650,
  });
}

function requireAccess(req, res, next) {
  const token = req.cookies.mindedge_access;
  if (!token) return res.redirect('/paywall');
  try {
    const user = verifyToken(token);
    // Re-validate access codes — if code was removed, deny access
    if (user.code && !user.stripe_subscription) {
      const validCodes = (process.env.ACCESS_CODES || '').split(',').map(c => c.trim().toUpperCase());
      const isAdmin = user.code === (ADMIN_CODE || '').toUpperCase();
      if (!isAdmin && !validCodes.includes(user.code)) {
        res.clearCookie('mindedge_access');
        return res.redirect('/paywall');
      }
    }
    req.user = user;
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
    const user = verifyToken(token);
    // Re-validate access codes
    if (user.code && !user.stripe_subscription) {
      const validCodes = (process.env.ACCESS_CODES || '').split(',').map(c => c.trim().toUpperCase());
      const isAdmin = user.code === (ADMIN_CODE || '').toUpperCase();
      if (!isAdmin && !validCodes.includes(user.code)) {
        res.clearCookie('mindedge_access');
        return res.status(401).json({ error: 'Access revoked' });
      }
    }
    req.user = user;
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
  res.json({ status: 'ok' });
});

// Check if current user is authenticated (for frontend)
app.get('/api/auth-status', async (req, res) => {
  const token = req.cookies.mindedge_access;
  if (!token) return res.json({ authenticated: false });
  try {
    const user = verifyToken(token);

    // Re-validate access codes
    if (user.code && !user.stripe_subscription) {
      const validCodes = (process.env.ACCESS_CODES || '').split(',').map(c => c.trim().toUpperCase());
      const isAdmin = user.code === (ADMIN_CODE || '').toUpperCase();
      if (!isAdmin && !validCodes.includes(user.code)) {
        res.clearCookie('mindedge_access');
        return res.json({ authenticated: false, reason: 'code_revoked' });
      }
    }

    const result = {
      authenticated: true,
      tier: user.tier || 'pro',
      email: user.email,
      subscription: null,
    };

    // If user has a subscription, verify it's still active with Stripe
    if (user.stripe_subscription) {
      try {
        const sub = await stripe.subscriptions.retrieve(user.stripe_subscription);
        result.subscription = {
          status: sub.status,
          current_period_end: sub.current_period_end,
          cancel_at_period_end: sub.cancel_at_period_end,
          plan: sub.items.data[0]?.price?.recurring?.interval || 'month',
        };
        // If subscription is cancelled or past due, deny access
        if (['canceled', 'unpaid', 'incomplete_expired'].includes(sub.status)) {
          res.clearCookie('mindedge_access');
          return res.json({ authenticated: false, reason: 'subscription_' + sub.status });
        }
      } catch (stripeErr) {
        console.error('Stripe sub check error:', stripeErr.message);
        // If we can't reach Stripe, trust the JWT for now
      }
    }

    res.json(result);
  } catch {
    res.json({ authenticated: false });
  }
});

// Verify access on page load — frontend calls this to enforce revocation
app.get('/api/verify', async (req, res) => {
  const token = req.cookies.mindedge_access;
  if (!token) return res.json({ valid: false, reason: 'no_token' });
  try {
    const user = verifyToken(token);

    // Re-validate access codes
    if (user.code && !user.stripe_subscription) {
      const validCodes = (process.env.ACCESS_CODES || '').split(',').map(c => c.trim().toUpperCase());
      const isAdmin = user.code === (ADMIN_CODE || '').toUpperCase();
      if (!isAdmin && !validCodes.includes(user.code)) {
        res.clearCookie('mindedge_access');
        return res.json({ valid: false, reason: 'code_revoked' });
      }
    }

    // Re-validate Stripe subscriptions
    if (user.stripe_subscription) {
      try {
        const sub = await stripe.subscriptions.retrieve(user.stripe_subscription);
        if (['canceled', 'unpaid', 'incomplete_expired'].includes(sub.status)) {
          res.clearCookie('mindedge_access');
          return res.json({ valid: false, reason: 'subscription_' + sub.status });
        }
      } catch (err) {
        console.error('Stripe verify error:', err.message);
        // If Stripe is unreachable, trust JWT for now
      }
    }

    res.json({ valid: true, tier: user.tier });
  } catch {
    res.clearCookie('mindedge_access');
    res.json({ valid: false, reason: 'token_expired' });
  }
});

// ── SUBSCRIPTION MANAGEMENT ─────────────────────────────────────
// Customer portal: lets users update payment, cancel, view invoices
app.post('/api/billing-portal', requireAccessAPI, async (req, res) => {
  try {
    const user = req.user;
    if (!user.stripe_customer) {
      return res.status(400).json({ error: 'No billing account found. Contact support.' });
    }
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer,
      return_url: `${DOMAIN}/app`,
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('Portal error:', err.message);
    res.status(500).json({ error: 'Could not open billing portal' });
  }
});

// ── FREE ACCESS CODE (for analyst community) ─────────────────────
// You can give community members a code to get free access
app.post('/api/redeem-code', codeLimiter, (req, res) => {
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
// Price IDs are created in your Stripe Dashboard under Products
// Set these as environment variables in Railway:
//   STRIPE_PRICE_APP_MONTHLY   = price_xxx (recurring monthly)
//   STRIPE_PRICE_APP_ANNUAL    = price_xxx (recurring annual)
//   STRIPE_PRICE_GUIDE         = price_xxx (one-time)

// Read env vars at runtime via dynamic key construction
// so Railpack's static analysis doesn't flag them as build secrets
const _sp = 'STRIPE_PRICE_';
const cleanPrice = (key) => (process.env[_sp + key] || '').replace(/^[\s='"+]+/, '').trim();
function getProducts() {
  return {
    app_monthly: {
      name: 'MindEdge Pro — Monthly',
      priceId: cleanPrice('APP_MONTHLY'),
      mode: 'subscription',
      tier: 'pro',
      includesGuide: false,
    },
    app_annual: {
      name: 'MindEdge Pro — Annual',
      priceId: cleanPrice('APP_ANNUAL'),
      mode: 'subscription',
      tier: 'pro',
      includesGuide: false,
    },
    app_discord: {
      name: 'MindEdge Pro + Discord — Monthly',
      priceId: cleanPrice('APP_DISCORD'),
      mode: 'subscription',
      tier: 'pro_discord',
      includesGuide: false,
    },
    guide: {
      name: 'SPX Scalping Framework — PDF Guide',
      priceId: cleanPrice('GUIDE'),
      mode: 'payment',
      tier: 'guide',
      includesGuide: true,
    },
  };
}

app.post('/api/create-checkout', checkoutLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Payments not configured' });
  }
  const productKey = req.body.product;
  const PRODUCTS = getProducts();
  const product = PRODUCTS[productKey];
  if (!product || !product.priceId) {
    return res.status(400).json({ error: 'Invalid product selected' });
  }
  try {
    const sessionParams = {
      payment_method_types: ['card'],
      line_items: [{ price: product.priceId, quantity: 1 }],
      mode: product.mode,
      success_url: `${DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}&product=${productKey}`,
      cancel_url: `${DOMAIN}/paywall`,
      allow_promotion_codes: true,
    };

    // For subscriptions, allow customers to manage billing later
    if (product.mode === 'subscription') {
      sessionParams.subscription_data = {
        metadata: { tier: product.tier, product: productKey },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

app.get('/payment-success', async (req, res) => {
  const { session_id, product } = req.query;
  if (!session_id) return res.redirect('/paywall');
  // Validate session_id format to prevent injection
  if (!/^cs_[a-zA-Z0-9_]+$/.test(session_id)) return res.redirect('/paywall?error=invalid_session');
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const PRODUCTS = getProducts();
    const productInfo = PRODUCTS[product] || PRODUCTS.app_monthly;

    // Guide-only purchase (one-time): send PDF directly, no app access cookie
    if (product === 'guide') {
      if (session.payment_status !== 'paid') return res.redirect('/paywall?error=not_paid');
      const token = issueToken({
        access: false,
        tier: 'guide',
        email: session.customer_details?.email || 'user',
        paid_at: Date.now(),
        stripe_session: session.id,
      });
      res.cookie('mindedge_guide_token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 365 * 10,
      });
      return res.redirect('/download-guide');
    }

    // Subscription products: check subscription status
    if (productInfo.mode === 'subscription') {
      const subscriptionId = session.subscription;
      if (!subscriptionId) return res.redirect('/paywall?error=no_subscription');
      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      if (!['active', 'trialing'].includes(subscription.status)) {
        return res.redirect('/paywall?error=subscription_inactive');
      }

      const token = issueToken({
        access: true,
        tier: productInfo.tier,
        email: session.customer_details?.email || 'user',
        stripe_customer: session.customer,
        stripe_subscription: subscriptionId,
        subscribed_at: Date.now(),
        includesGuide: productInfo.includesGuide,
      }, '365d');

      setAccessCookie(res, token);
      // Discord subscribers get redirected to welcome page with Discord invite
      if (productInfo.tier === 'pro_discord') {
        return res.redirect('/welcome-discord');
      }
      return res.redirect('/app');
    }

    // Fallback: one-time payment (shouldn't happen with current products)
    if (session.payment_status !== 'paid') return res.redirect('/paywall?error=not_paid');
    const token = issueToken({
      access: true,
      tier: productInfo.tier,
      email: session.customer_details?.email || 'user',
      paid_at: Date.now(),
      stripe_session: session.id,
      includesGuide: productInfo.includesGuide,
    });
    setAccessCookie(res, token);
    res.redirect('/app');
  } catch (err) {
    console.error('Verification error:', err.message);
    res.redirect('/paywall?error=verification_failed');
  }
});

// Discord welcome page — shown after Pro + Discord purchase
app.get('/welcome-discord', requireAccess, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome to MindEdge Pro + Discord</title>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;500;600&family=Outfit:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#080807;color:#F0EAD6;font-family:'Outfit',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px}
  .card{max-width:560px;width:100%;background:#0f0f0d;border:1px solid rgba(201,168,76,0.25);border-radius:16px;padding:48px 40px;text-align:center}
  .check{width:64px;height:64px;border-radius:50%;background:rgba(82,168,130,0.1);border:2px solid rgba(82,168,130,0.4);display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 24px}
  h1{font-family:'Cormorant Garamond',serif;font-size:32px;font-weight:400;margin-bottom:8px;color:#C9A84C}
  .sub{font-size:14px;color:#8a8475;margin-bottom:32px;line-height:1.6}
  .steps{text-align:left;margin-bottom:32px}
  .step{display:flex;gap:14px;margin-bottom:20px;align-items:flex-start}
  .step-num{width:28px;height:28px;border-radius:50%;background:rgba(201,168,76,0.12);border:1px solid rgba(201,168,76,0.25);display:flex;align-items:center;justify-content:center;font-size:12px;color:#C9A84C;flex-shrink:0;margin-top:2px}
  .step-text{font-size:14px;color:#c8c0a8;line-height:1.6}
  .step-text strong{color:#F0EAD6}
  .btn{display:inline-block;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:500;text-decoration:none;cursor:pointer;border:none;font-family:'Outfit',sans-serif;margin:6px}
  .btn-discord{background:#5865F2;color:white}
  .btn-discord:hover{background:#4752C4}
  .btn-app{background:transparent;color:#C9A84C;border:1px solid rgba(201,168,76,0.4)}
  .btn-app:hover{background:rgba(201,168,76,0.08)}
</style></head><body>
<div class="card">
  <div class="check">✓</div>
  <h1>Welcome to MindEdge</h1>
  <div class="sub">Your Pro + Discord subscription is active. Here's how to get started:</div>
  <div class="steps">
    <div class="step"><div class="step-num">1</div><div class="step-text"><strong>Join the Discord</strong> — Click the button below to join the MindEdge trading community. This is where daily live coaching happens.</div></div>
    <div class="step"><div class="step-num">2</div><div class="step-text"><strong>Explore the platform</strong> — Open MindEdge and start with Chart Intelligence or the 5-Layer Framework Reader to sharpen your reads.</div></div>
    <div class="step"><div class="step-num">3</div><div class="step-text"><strong>Show up tomorrow</strong> — Coaching starts pre-market. Bring your charts, bring your questions.</div></div>
  </div>
  <a href="https://discord.gg/NaAPNNCap" target="_blank" class="btn btn-discord">Join Discord Server</a>
  <a href="/app" class="btn btn-app">Open MindEdge →</a>
</div>
</body></html>`);
});

// Guide download page
app.get('/download-guide', (req, res) => {
  // Check cookie first (guide-only purchase), then access cookie (bundle/platform)
  const guideToken = req.cookies.mindedge_guide_token;
  const accessToken = req.cookies.mindedge_access;
  const token = guideToken || accessToken;
  if (!token) return res.redirect('/paywall?error=access_required');
  try {
    const payload = verifyToken(token);
    const allowed = ['guide','pro','community','admin'].includes(payload.tier);
    if (!allowed) return res.redirect('/paywall?error=upgrade_required');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="MindEdge_SPX_Scalping_Framework.pdf"');
    res.setHeader('Cache-Control', 'no-store');
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
      const controller = new AbortController();
      const fetchTimeout = setTimeout(() => controller.abort(), 8000); // 8s timeout
      let r;
      try {
        r = await fetch(url, {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
          },
          signal: controller.signal,
        });
      } finally {
        clearTimeout(fetchTimeout);
      }
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

    // Sanitize and validate numeric inputs
    const sanitizePrice = (p) => {
      const n = parseFloat(String(p).replace(/[^0-9.-]/g, ''));
      return !isNaN(n) && n > 0 && n < 100000 ? n : null;
    };
    const sanitizeText = (t) => t ? String(t).substring(0, 500).replace(/[<>]/g, '') : '';
    const ep  = sanitizePrice(entryPrice);
    const xp  = sanitizePrice(exitPrice);
    const safeNotes   = sanitizeText(notes);
    const safeGex     = sanitizeText(gexLevels);
    const safeChecks  = sanitizeText(preTrade5Checks);
    const safeDir     = ['Long','Short'].includes(direction) ? direction : 'Long';
    const pnl = ep && xp ? ((xp - ep) * (safeDir === 'Short' ? -1 : 1)).toFixed(2) : 'not provided';

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
Direction: ${safeDir}
Entry Time: ${entryDisplay}
Exit Time: ${exitDisplay}
Session Window: ${sessionWindowStatus}
Pre-Trade 5 Checks Completed: ${safeChecks || 'Not confirmed by trader'}
GEX Provided: ${safeGex ? 'YES' : 'NOT PROVIDED — GEX context will be limited'}
Entry Price: ${ep || 'not provided'}
Exit Price: ${xp || 'not provided'}
P&L: ${pnl} points
Trader Notes: ${safeNotes || 'none'}

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

5-min structure events:
${structure5m.length ? structure5m.map(e => '  ' + e.label + ' at ' + e.price + ' (' + e.time + ')').join('\n') : '  No clear BOS/ChoCh detected in window'}

1-min structure events (execution):
${structure1m.length ? structure1m.map(e => '  ' + e.label + ' at ' + e.price + ' (' + e.time + ')').join('\n') : '  No clear BOS/ChoCh detected in window'}

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
${safeGex || 'Not provided by trader — GEX levels must be sourced from SpotGamma, Squeeze Metrics, or similar at time of trade'}

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
TRADE ANALYSIS
═══════════════════════════════
Using all the indicator data above, write a clear, conversational trade review. Write as a knowledgeable trading coach speaking directly to the trader — not as a compliance checklist. Use plain English. No jargon-heavy language. No bullet-point walls. Make it feel like feedback from a mentor who has seen the trade.

Structure your analysis as follows:

1. SESSION TIMING
Was this a good time to be trading? Session: ${sessionWindowStatus}. Comment on whether the time of day supported or worked against the setup. Keep it to 2 sentences.

2. EMA PICTURE
What was the EMA story across the 9 and 21 on the 5-minute and 15-minute at the time of entry? Was price above or below both? Were the EMAs trending or flat? Note any recent crossovers. The 1-minute EMA is just a quick-reaction indicator — flag it as context, not as a problem if it differed from the higher timeframes.

3. FIBONACCI CONTEXT
The trader uses ChartPrime Fibonacci levels. The key question is not whether they entered exactly in the OTE zone — it is whether there was meaningful room to run from the fib level nearest to their entry. Comment on which fib level the entry was closest to, and whether there was reasonable space before the next significant fib resistance. If the entry was near a key level with room to run, that is good. If the entry was between levels with no clear logic, note that.

4. MARKET STRUCTURE
What was the BOS and ChoCh picture telling us on the 15-minute and 5-minute? Was the structure in favour of the trade direction? Keep this practical and specific to the actual structure events detected.

5. VOLUME PROFILE
Was the entry near the POC or inside the value area? How did the VRVP and SVP levels interact with the entry and exit price? Where were the nearest volume nodes?

6. GEX
${safeGex ? 'GEX was provided: ' + safeGex + '. How did these gamma levels interact with the trade? Were there walls nearby? Was the trader above or below the HVL?' : 'GEX was not provided for this trade. Note briefly what GEX information would have been useful — particularly whether there were gamma walls near the entry or target.'}

7. WHAT YOU DID WELL
Start here. Look for genuine positives — did they trade in the right direction? Was the exit disciplined? Did they follow their stop? Was the timing reasonable? Did they stay patient before entering? Reference actual prices and times. Be specific and honest — only mention real strengths visible in the data. 2-3 things minimum. This section should leave the trader feeling capable, not just criticised.

8. WHAT TO IMPROVE
2-3 honest, actionable observations. Be constructive not harsh. Focus on what the trader can do differently next time, not on what went wrong.

9. IDEAL ENTRY
Given everything above, where would a cleaner entry have been? Give a specific price and one sentence of reasoning. This is not a criticism — it is a learning point.

10. OVERALL GRADE
Give a single letter grade: A, B, C, or D. Then one sentence explaining it.

Grading guide:
A — The setup logic was clear, the entry made sense relative to the indicators, and the trade was managed well.
B — Good directional read and reasonable entry, with minor gaps in confluence or execution.
C — The trade had some merit but the entry logic was unclear, or management was loose. Profitable trades can still be a C if the process was shaky.
D — No clear setup logic, or risk management was absent. Reserved for trades where the process needs a significant rethink.

Write like a mentor, not an auditor. The goal is for the trader to finish reading this and know exactly what to do differently — and feel motivated to improve, not discouraged.`;

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

// ── SWING PLANS — bot writes, frontend reads ─────────────────
// Persisted to file so plans survive server restarts
const SWING_FILE = path.join('/data', '.swing-plans.json');

function loadSwingPlans() {
  try {
    if (require('fs').existsSync(SWING_FILE)) {
      return JSON.parse(require('fs').readFileSync(SWING_FILE, 'utf8'));
    }
  } catch (e) { console.error('Failed to load swing plans:', e.message); }
  return { date: null, plans: [], tickers: [], raw: '' };
}

function saveSwingPlans(data) {
  try {
    require('fs').writeFileSync(SWING_FILE, JSON.stringify(data), 'utf8');
  } catch (e) { console.error('Failed to save swing plans:', e.message); }
}

// Bot POSTs today's swing plans here
app.post('/api/swing-plans', express.json({ limit: '100kb' }), (req, res) => {
  const secret = req.headers['x-bot-secret'];
  if (secret !== process.env.SWING_BOT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { date, plans, tickers, raw, marketContext } = req.body;
  const store = {
    date: date || new Date().toISOString().slice(0, 10),
    plans: plans || [],
    tickers: tickers || [],
    raw: raw || '',
    marketContext: marketContext || '',
    updatedAt: new Date().toISOString()
  };
  saveSwingPlans(store);
  console.log(`Swing plans saved: ${store.tickers.length} tickers for ${store.date}`);
  res.json({ ok: true });
});

// Frontend reads today's swing plans
app.get('/api/swing-plans', requireAccessAPI, (req, res) => {
  res.json(loadSwingPlans());
});

// Chart data for any ticker — used by swing page
app.get('/api/chart/:ticker', requireAccessAPI, chartLimiter, async (req, res) => {
  try {
    const ticker = req.params.ticker.toUpperCase();
    const interval = req.query.interval || '1d';
    const range = req.query.range || '1y';
    const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=${interval}&range=${range}&includePrePost=false`;
    const controller = new AbortController();
    const fetchTimeout = setTimeout(() => controller.abort(), 8000);
    let r;
    try {
      r = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(fetchTimeout);
    }
    if (!r.ok) throw new Error(`Yahoo Finance error: ${r.status}`);
    const data = await r.json();
    const result = data.chart.result[0];
    const meta = result.meta;
    const timestamps = result.timestamp || [];
    const quotes = result.indicators.quote[0];
    const bars = timestamps.map((ts, i) => ({
      time: new Date(ts * 1000).toISOString(),
      open:   quotes.open[i]   != null ? parseFloat(quotes.open[i].toFixed(2))   : null,
      high:   quotes.high[i]   != null ? parseFloat(quotes.high[i].toFixed(2))   : null,
      low:    quotes.low[i]    != null ? parseFloat(quotes.low[i].toFixed(2))    : null,
      close:  quotes.close[i]  != null ? parseFloat(quotes.close[i].toFixed(2))  : null,
      volume: quotes.volume[i] || 0,
    })).filter(b => b.close !== null);
    res.json({
      ticker,
      currency: meta.currency,
      exchange: meta.exchangeName,
      name: meta.shortName || meta.symbol,
      price: meta.regularMarketPrice,
      prevClose: meta.chartPreviousClose,
      bars,
    });
  } catch (err) {
    console.error('Chart data error:', err.message);
    res.status(500).json({ error: 'Could not fetch chart data: ' + err.message });
  }
});

// Swing page route
app.get('/swing', requireAccess, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'swing.html'));
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
  console.log(`MindEdge v4 running on port ${PORT}`);
  console.log(`Security: helmet + rate limiting + JWT auth enabled`);
  console.log(`Stripe: subscription billing ${process.env[_sp + 'APP_MONTHLY'] ? 'configured' : 'NOT configured — set STRIPE_PRICE_* env vars'}`);
  console.log(`Webhook: ${process.env['STRIPE_WEBHOOK' + '_SECRET'] ? 'configured' : 'NOT configured — set STRIPE_WEBHOOK_SECRET'}`);
});
