# MindEdge — Trading Psychology Platform

AI-powered trading psychology coach drawing from Mark Douglas, Dr. Brett Steenbarger, Dr. Van Tharp, Dr. Alexander Elder, Jesse Livermore, and Daniel Kahneman.

---

## Deploy in 5 Minutes (Railway — Recommended)

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
gh repo create mindedge --public --push
# or manually push to your GitHub account
```

### 2. Deploy on Railway
1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **New Project → Deploy from GitHub repo**
3. Select your `mindedge` repo
4. Railway auto-detects Node.js and deploys

### 3. Add your API key
1. In Railway dashboard → your project → **Variables**
2. Add: `ANTHROPIC_API_KEY` = `sk-ant-your-key-here`
3. Get your key from [console.anthropic.com](https://console.anthropic.com)
4. Railway auto-restarts — your app is live!

---

## Deploy on Render (Alternative Free Option)

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Set:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Add environment variable: `ANTHROPIC_API_KEY`
5. Deploy

---

## Run Locally

```bash
# 1. Install dependencies
npm install

# 2. Set up your API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Start the server
npm start

# Visit http://localhost:3000
```

---

## Project Structure

```
mindedge/
├── server.js          # Express backend — proxies Claude API
├── package.json
├── .env.example       # Copy to .env with your API key
├── .gitignore         # Excludes .env and node_modules
└── public/
    └── index.html     # Full frontend (self-contained)
```

## How It Works

- The frontend calls `/api/chat` on your own server
- Your server holds the Anthropic API key securely in an environment variable
- Your key is never exposed to the browser or public
- All Claude API calls are proxied through your backend

---

## Estimated Costs

At Claude Sonnet pricing (~$3 per million input tokens):
- Each coaching response ≈ 500–800 tokens
- 1,000 sessions/month ≈ ~$3–5/month
- Railway free tier: 500 hours/month (enough for personal use)
- 
