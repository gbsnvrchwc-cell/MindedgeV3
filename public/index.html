// src/index.js
import 'dotenv/config';
import { Client, GatewayIntentBits, EmbedBuilder, ActivityType } from 'discord.js';
import { getAnalystResponse, getStoreHealth } from './analyst.js';
import { getQuote, getTechnicals, getOptionsChain, getEarningsCalendar, getMomentumStocks, getMacroSnapshot } from './market.js';
import Anthropic from '@anthropic-ai/sdk';

const ai = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const ANALYST_NAME  = process.env.ANALYST_NAME  || 'The Analyst';
const ANALYST_TITLE = process.env.ANALYST_TITLE || 'Senior Analyst';
const ANALYST_FIRM  = process.env.ANALYST_FIRM  || 'Research Desk';
const ANALYST_FOCUS = process.env.ANALYST_FOCUS || 'Equities & Options';

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages] });

// ─── Ready ────────────────────────────────────────────────────────────────────

client.once('ready', () => {
  console.log(`\n✅ ${ANALYST_NAME} Bot online as: ${client.user.tag}`);
  const health = getStoreHealth();
  if (health.ready) {
    console.log(`📚 ${health.totalChunks} chunks from ${health.sources.length} source(s): ${health.sources.join(', ')}`);
  } else {
    console.warn(`⚠️  No research loaded. Run: npm run ingest ./docs`);
  }
  client.user.setActivity(`/ask /analyze /scan /scalp | ${ANALYST_FIRM}`, { type: ActivityType.Watching });
});

// ─── Commands ─────────────────────────────────────────────────────────────────

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  const { commandName } = interaction;

  // ── /ask ───────────────────────────────────────────────────────────────────
  if (commandName === 'ask') {
    const question = interaction.options.getString('question');
    await interaction.deferReply();
    try {
      const { answer, sources } = await getAnalystResponse(question);
      const embed = new EmbedBuilder()
        .setColor(0x1a56db)
        .setAuthor({ name: `${ANALYST_NAME} · ${ANALYST_TITLE}` })
        .setTitle(`💬 ${truncate(question, 200)}`)
        .setDescription(answer)
        .setFooter({ text: sources.length > 0 ? `📁 ${sources.join(' · ')}` : '⚠️ General knowledge response' })
        .setTimestamp();
      await interaction.editReply({ embeds: [embed] });
    } catch (err) {
      console.error('/ask error:', err);
      await interaction.editReply({ content: '❌ Error generating response. Try again.' });
    }
  }

  // ── /analyze ───────────────────────────────────────────────────────────────
  if (commandName === 'analyze') {
    const ticker    = interaction.options.getString('ticker').toUpperCase();
    const direction = interaction.options.getString('direction') || 'neutral';
    await interaction.deferReply();

    try {
      const [quoteResult, techResult, optionsResult] = await Promise.allSettled([
        getQuote(ticker),
        getTechnicals(ticker),
        getOptionsChain(ticker),
      ]);

      const q = quoteResult.status   === 'fulfilled' ? quoteResult.value   : null;
      const t = techResult.status    === 'fulfilled' ? techResult.value    : null;
      const o = optionsResult.status === 'fulfilled' ? optionsResult.value : null;

      if (!q) throw new Error(`Could not fetch data for ${ticker}`);

      const atrPct = t ? ((t.atr14 / q.price) * 100).toFixed(2) : 'N/A';
      const rsi    = t?.rsi14 ?? 'N/A';

      let momentumFlag = '';
      if (typeof rsi === 'number') {
        if (rsi > 70 && direction !== 'bearish') momentumFlag = '🚫 RSI OVERBOUGHT (>70) — Framework says NO calls here.';
        if (rsi < 30 && direction !== 'bullish') momentumFlag = '🚫 RSI OVERSOLD (<30) — Framework says NO puts here.';
      }

      const candidates = direction === 'bearish' ? (o?.topPuts || []) : (o?.topCalls || []);
      const optionLines = candidates.slice(0, 3).map(c =>
        `**Strike $${c.strike}** | Delta ${c.delta?.toFixed(2) ?? 'N/A'} | IV ${c.iv} | OI ${(c.openInterest||0).toLocaleString()} | Vol ${(c.volume||0).toLocaleString()} | Score ${c.score}/8\n${[...c.reasons, ...c.flags].join(' · ')}`
      ).join('\n\n') || 'No qualifying options found matching framework criteria (OI <500, IV >75%, or Delta out of range).';

      const dataSummary = [
        `TICKER: ${ticker} (${q.name})`,
        `PRICE: $${q.price} (${q.changePct > 0 ? '+' : ''}${q.changePct?.toFixed(2)}%)`,
        `VOLUME: ${(q.volume||0).toLocaleString()} vs Avg ${(q.avgVolume||0).toLocaleString()}`,
        `52W: High $${q.fiftyTwoHigh} / Low $${q.fiftyTwoLow}`,
        `RSI(14): ${rsi}${typeof rsi === 'number' ? (rsi > 70 ? ' ⚠️ OVERBOUGHT' : rsi < 30 ? ' ⚠️ OVERSOLD' : ' ✅') : ''}`,
        `ATR(14): $${t?.atr14 ?? 'N/A'} (${atrPct}% of price)${parseFloat(atrPct) >= 2 ? ' ✅' : ' ⚠️ Low — option may not move enough'}`,
        `SMA20: $${t?.sma20 ?? 'N/A'} | SMA50: $${t?.sma50 ?? 'N/A'}`,
        `DIRECTION: ${direction}`,
        momentumFlag ? `\nMOMENTUM WARNING: ${momentumFlag}` : '',
        `\nTOP OPTION CANDIDATES (scored against framework):\n${optionLines}`,
        `\nNEAREST EXPIRY: ${o?.expiryDate ? new Date(o.expiryDate).toDateString() : 'N/A'}`,
      ].filter(Boolean).join('\n');

      const aiResponse = await ai.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 800,
        system: buildAnalystSystem(),
        messages: [{ role: 'user', content: `Analyze this options swing trade opportunity:\n\n${dataSummary}` }],
      });

      const embed = new EmbedBuilder()
        .setColor(momentumFlag ? 0xe74c3c : direction === 'bearish' ? 0xe67e22 : 0x2ecc71)
        .setTitle(`📊 ${ticker} — Options Analysis`)
        .setDescription(aiResponse.content[0].text)
        .addFields(
          { name: 'Price',    value: `$${q.price}`,              inline: true },
          { name: 'RSI(14)',  value: `${rsi}`,                   inline: true },
          { name: 'ATR(14)',  value: `$${t?.atr14 ?? 'N/A'} (${atrPct}%)`, inline: true },
        )
        .setFooter({ text: `Yahoo Finance · Not financial advice · ${new Date().toLocaleTimeString()}` })
        .setTimestamp();

      await interaction.editReply({ embeds: [embed] });

    } catch (err) {
      console.error('/analyze error:', err);
      await interaction.editReply({ content: `❌ Could not analyze **${ticker}**: ${err.message}` });
    }
  }

  // ── /scan ──────────────────────────────────────────────────────────────────
  if (commandName === 'scan') {
    const mode = interaction.options.getString('mode');
    await interaction.deferReply();

    try {
      // ── MODE: EARNINGS ─────────────────────────────────────────────────────
      if (mode === 'earnings') {
        const earnings = await getEarningsCalendar();
        if (earnings.length === 0) {
          await interaction.editReply({ content: '📭 No upcoming earnings in the next 21 days.' });
          return;
        }
        const earningsList = earnings.slice(0, 15).map(e =>
          `${e.ticker} (${e.name}) — in ${e.daysUntil}d on ${e.earningsDate.toDateString()} | $${e.price?.toFixed(2)} | ${e.changePct > 0 ? '+' : ''}${e.changePct?.toFixed(2)}% | AvgVol ${(e.volume||0).toLocaleString()}`
        ).join('\n');

        const ai1 = await ai.messages.create({
          model: 'claude-sonnet-4-20250514', max_tokens: 700, system: buildAnalystSystem(),
          messages: [{ role: 'user', content: `Earnings catalysts coming up. Using my swing framework (ATR >2%, OI 4000+, IV <75%, RSI not at extremes), which 3–4 look best for pre-earnings momentum plays? Flag any to avoid.\n\n${earningsList}` }],
        });

        const soon   = earnings.filter(e => e.daysUntil <= 7).slice(0, 5);
        const coming = earnings.filter(e => e.daysUntil > 7).slice(0, 5);
        const embed = new EmbedBuilder()
          .setColor(0xf39c12).setTitle('📅 Earnings Catalyst Scan — Next 21 Days')
          .setDescription(ai1.content[0].text)
          .addFields(
            { name: '🔥 This Week',  value: soon.map(e   => `**${e.ticker}** ${e.daysUntil}d · $${e.price?.toFixed(2)} · ${e.changePct > 0 ? '+' : ''}${e.changePct?.toFixed(2)}%`).join('\n') || 'None', inline: true },
            { name: '📅 Coming Up', value: coming.map(e => `**${e.ticker}** ${e.daysUntil}d · $${e.price?.toFixed(2)}`).join('\n') || 'None', inline: true },
          )
          .setFooter({ text: `${earnings.length} names scanned · /analyze <ticker> for full breakdown` }).setTimestamp();
        await interaction.editReply({ embeds: [embed] });
      }

      // ── MODE: MOMENTUM ─────────────────────────────────────────────────────
      else if (mode === 'momentum') {
        const movers = await getMomentumStocks();
        if (movers.length === 0) {
          await interaction.editReply({ content: '📭 No strong momentum stocks detected right now.' });
          return;
        }
        const moversList = movers.slice(0, 12).map(m =>
          `${m.ticker} (${m.name}) — ${m.changePct > 0 ? '+' : ''}${m.changePct?.toFixed(2)}% | Vol ${m.volRatio}x avg | $${m.price?.toFixed(2)} | Score ${m.momentumScore} | ${m.direction}`
        ).join('\n');

        const ai2 = await ai.messages.create({
          model: 'claude-sonnet-4-20250514', max_tokens: 700, system: buildAnalystSystem(),
          messages: [{ role: 'user', content: `These stocks are showing RSI momentum and volume surges right now. Using my swing framework, which 3–4 are worth setting up a trade on? Which should I avoid? Flag RSI extremes.\n\n${moversList}` }],
        });

        const bulls = movers.filter(m => m.direction === 'bullish').slice(0, 4);
        const bears = movers.filter(m => m.direction === 'bearish').slice(0, 4);
        const embed = new EmbedBuilder()
          .setColor(0x2ecc71).setTitle('🚀 Momentum Scan — RSI + Volume Surge')
          .setDescription(ai2.content[0].text)
          .addFields(
            { name: '🟢 Bullish Movers', value: bulls.map(m => `**${m.ticker}** +${m.changePct?.toFixed(2)}% · ${m.volRatio}x vol`).join('\n') || 'None', inline: true },
            { name: '🔴 Bearish Movers', value: bears.map(m => `**${m.ticker}** ${m.changePct?.toFixed(2)}% · ${m.volRatio}x vol`).join('\n') || 'None', inline: true },
          )
          .setFooter({ text: `${movers.length} momentum stocks found · /analyze <ticker> for options breakdown` }).setTimestamp();
        await interaction.editReply({ embeds: [embed] });
      }

      // ── MODE: COMBINED ─────────────────────────────────────────────────────
      else if (mode === 'combined') {
        const [earnings, movers] = await Promise.all([getEarningsCalendar(), getMomentumStocks()]);

        // Find tickers appearing in BOTH lists
        const earningsTickers = new Set(earnings.map(e => e.ticker));
        const crossover = movers.filter(m => earningsTickers.has(m.ticker));

        // Also include high-score movers near earnings (within 14 days)
        const earningsMap = Object.fromEntries(earnings.map(e => [e.ticker, e]));
        const nearEarnings = movers
          .filter(m => earningsMap[m.ticker]?.daysUntil <= 14)
          .slice(0, 8);

        const combinedList = [...new Map([...crossover, ...nearEarnings].map(m => [m.ticker, m])).values()];

        const dataStr = combinedList.slice(0, 10).map(m => {
          const e = earningsMap[m.ticker];
          return `${m.ticker} — ${m.changePct > 0 ? '+' : ''}${m.changePct?.toFixed(2)}% | ${m.volRatio}x vol | ${e ? `Earnings in ${e.daysUntil}d` : 'No earnings soon'} | Score ${m.momentumScore}`;
        }).join('\n');

        const earningsOnlyStr = earnings.slice(0, 8).map(e =>
          `${e.ticker} — Earnings in ${e.daysUntil}d | $${e.price?.toFixed(2)} | ${e.changePct > 0 ? '+' : ''}${e.changePct?.toFixed(2)}%`
        ).join('\n');

        const ai3 = await ai.messages.create({
          model: 'claude-sonnet-4-20250514', max_tokens: 800, system: buildAnalystSystem(),
          messages: [{ role: 'user', content: `Combined scan: stocks showing momentum AND upcoming earnings. These are the highest-conviction setups. Apply my full swing framework and rank the top 3–4 plays. Flag any with RSI extremes or other issues.\n\nMOMENTUM + EARNINGS:\n${dataStr || 'None found'}\n\nEARNINGS ONLY (no momentum yet):\n${earningsOnlyStr}` }],
        });

        const embed = new EmbedBuilder()
          .setColor(0xe74c3c).setTitle('🔥 Combined Scan — Momentum + Earnings Catalyst')
          .setDescription(ai3.content[0].text)
          .addFields({
            name: '⚡ Momentum + Earnings',
            value: combinedList.slice(0, 5).map(m => {
              const e = earningsMap[m.ticker];
              return `**${m.ticker}** ${m.changePct > 0 ? '+' : ''}${m.changePct?.toFixed(2)}% · ${m.volRatio}x vol${e ? ` · Earnings ${e.daysUntil}d` : ''}`;
            }).join('\n') || 'No overlap found — try Earnings or Momentum modes separately',
            inline: false,
          })
          .setFooter({ text: 'Combined mode finds highest-conviction setups · /analyze <ticker> for full breakdown' }).setTimestamp();
        await interaction.editReply({ embeds: [embed] });
      }

      // ── MODE: MACRO ────────────────────────────────────────────────────────
      else if (mode === 'macro') {
        const [macro, movers, earnings] = await Promise.all([
          getMacroSnapshot(),
          getMomentumStocks(),
          getEarningsCalendar(),
        ]);

        const macroStr = Object.entries(macro).map(([label, d]) =>
          `${label}: $${d.price?.toFixed(2) ?? 'N/A'} (${d.changePct > 0 ? '+' : ''}${d.changePct?.toFixed(2) ?? 'N/A'}%)`
        ).join('\n');

        const topMovers   = movers.slice(0, 8).map(m => `${m.ticker} ${m.changePct > 0 ? '+' : ''}${m.changePct?.toFixed(2)}% · ${m.volRatio}x vol`).join(', ');
        const topEarnings = earnings.slice(0, 6).map(e => `${e.ticker} in ${e.daysUntil}d`).join(', ');

        const ai4 = await ai.messages.create({
          model: 'claude-sonnet-4-20250514', max_tokens: 900, system: buildAnalystSystem(),
          messages: [{ role: 'user', content: `Read the current macro environment and tell me what it means for swing trades right now. Then give me your top 3 trade ideas based on this macro context + the momentum and earnings data.

MACRO SNAPSHOT:\n${macroStr}\n\nTOP MOMENTUM STOCKS:\n${topMovers || 'None'}\n\nUPCOMING EARNINGS:\n${topEarnings || 'None'}\n\nAddress: (1) What is the macro environment saying? Risk-on or risk-off? (2) Which sectors or setups make sense given this? (3) Top 3 specific trade ideas with direction and rationale.` }],
        });

        const vix = macro['VIX'];
        const spx = macro['SPX'];
        const vixColor = vix?.changePct > 5 ? 0xe74c3c : vix?.changePct < -5 ? 0x2ecc71 : 0xf39c12;

        const embed = new EmbedBuilder()
          .setColor(vixColor).setTitle('🌐 Macro-Driven Scan — Market Environment Analysis')
          .setDescription(ai4.content[0].text)
          .addFields(
            { name: 'SPX',  value: `$${spx?.price?.toFixed(2) ?? 'N/A'} (${spx?.changePct > 0 ? '+' : ''}${spx?.changePct?.toFixed(2) ?? '?'}%)`, inline: true },
            { name: 'VIX',  value: `$${vix?.price?.toFixed(2) ?? 'N/A'} (${vix?.changePct > 0 ? '+' : ''}${vix?.changePct?.toFixed(2) ?? '?'}%)`, inline: true },
            { name: 'QQQ',  value: `$${macro['QQQ']?.price?.toFixed(2) ?? 'N/A'} (${macro['QQQ']?.changePct > 0 ? '+' : ''}${macro['QQQ']?.changePct?.toFixed(2) ?? '?'}%)`, inline: true },
          )
          .setFooter({ text: 'Macro mode reads SPX, VIX, QQQ, DXY, TLT, sectors · /analyze <ticker> to go deeper' }).setTimestamp();
        await interaction.editReply({ embeds: [embed] });
      }

    } catch (err) {
      console.error('/scan error:', err);
      await interaction.editReply({ content: `❌ Scan failed: ${err.message}` });
    }
  }

  // ── /scalp ─────────────────────────────────────────────────────────────────
  if (commandName === 'scalp') {
    const direction   = interaction.options.getString('direction');
    const confluences = interaction.options.getString('confluences') || '';
    await interaction.deferReply();

    try {
      const [spxQuote, spxTech] = await Promise.allSettled([
        getQuote('^GSPC'),
        getTechnicals('^GSPC'),
      ]);

      const spx  = spxQuote.status === 'fulfilled' ? spxQuote.value : null;
      const tech = spxTech.status  === 'fulfilled' ? spxTech.value  : null;

      // Session window check (ET)
      const now = new Date();
      const etStr  = now.toLocaleString('en-US', { timeZone: 'America/New_York', hour: '2-digit', minute: '2-digit', hour12: false });
      const [etH, etM] = etStr.split(':').map(Number);
      const etTime = etH + etM / 60;

      const sessionStatus =
        (etTime >= 9.5  && etTime <= 10.5) ? '✅ Open window (9:30–10:30am ET) — GO' :
        (etTime >= 15.0 && etTime <= 16.0) ? '✅ Power hour (3:00–4:00pm ET) — GO' :
        (etTime >= 11.5 && etTime < 15.0)  ? '🚫 LUNCH WINDOW — Do NOT trade (11:30am–2pm ET)' :
                                              '⚠️ Outside primary windows — be selective';

      const userConfluences = confluences.split(',').map(c => c.trim()).filter(Boolean);
      const confCount       = userConfluences.length;
      const confStatus      = confCount >= 3 ? `✅ ${confCount} confluences — meets minimum` : `🚫 Only ${confCount} — need at least 3`;

      const rsi = tech?.rsi14 ?? 'N/A';
      const rsiStatus =
        typeof rsi === 'number' && rsi > 70 && direction === 'long'  ? '🚫 SPX RSI overbought — caution on longs' :
        typeof rsi === 'number' && rsi < 30 && direction === 'short' ? '🚫 SPX RSI oversold — caution on shorts' :
        '✅ RSI clear';

      const checklistData = `
DIRECTION: ${direction.toUpperCase()}
SESSION WINDOW: ${sessionStatus}
CONFLUENCES (${confCount}): ${userConfluences.join(', ') || 'None stated'}
CONFLUENCE STATUS: ${confStatus}
SPX PRICE: ${spx?.price ?? 'N/A'}
SPX RSI(14): ${rsi} — ${rsiStatus}
SPX ATR(14): $${tech?.atr14 ?? 'N/A'}
SPX CHANGE: ${spx ? `${spx.changePct > 0 ? '+' : ''}${spx.changePct?.toFixed(2)}%` : 'N/A'}
      `.trim();

      const aiResponse = await ai.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 600,
        system: buildAnalystSystem(),
        messages: [{
          role: 'user',
          content: `Run the MindEdge SPX scalping pre-trade checklist for my ${direction} setup. Tell me what's confirmed, what I still need to verify (GEX, EMA stack, Fib zone, VRVP), and whether to proceed or wait.\n\n${checklistData}`,
        }],
      });

      const isGo = sessionStatus.startsWith('✅') && confCount >= 3;

      const embed = new EmbedBuilder()
        .setColor(isGo ? 0x2ecc71 : 0xe74c3c)
        .setTitle(`⚡ SPX Scalp Checklist — ${direction.toUpperCase()} ${isGo ? '🟢' : '🔴'}`)
        .setDescription(aiResponse.content[0].text)
        .addFields(
          { name: 'Session',     value: sessionStatus, inline: false },
          { name: 'Confluences', value: confStatus,     inline: false },
          { name: 'SPX RSI',     value: `${rsi}`,       inline: true  },
          { name: 'SPX ATR',     value: `$${tech?.atr14 ?? 'N/A'}`, inline: true },
        )
        .setFooter({ text: 'MindEdge v2.0 · Remember: 6/10 checklist boxes required · Not financial advice' })
        .setTimestamp();

      await interaction.editReply({ embeds: [embed] });

    } catch (err) {
      console.error('/scalp error:', err);
      await interaction.editReply({ content: `❌ Scalp check failed: ${err.message}` });
    }
  }

  // ── /research ──────────────────────────────────────────────────────────────
  if (commandName === 'research') {
    const health = getStoreHealth();
    const embed = new EmbedBuilder()
      .setColor(0x0f9d58)
      .setTitle(`📚 Research Library`)
      .setDescription(health.ready
        ? `**${health.totalChunks} chunks** across **${health.sources.length} document(s)**`
        : '⚠️ No documents loaded.')
      .setFooter({ text: 'Use /ask to query research' })
      .setTimestamp();
    if (health.ready) embed.addFields({ name: 'Documents', value: health.sources.map(s => `• \`${s}\``).join('\n') });
    await interaction.reply({ embeds: [embed], ephemeral: true });
  }

  // ── /analyst ───────────────────────────────────────────────────────────────
  if (commandName === 'analyst') {
    const health = getStoreHealth();
    const embed = new EmbedBuilder()
      .setColor(0x1a56db)
      .setTitle(`👤 ${ANALYST_NAME}`)
      .addFields(
        { name: 'Title',    value: ANALYST_TITLE, inline: true },
        { name: 'Firm',     value: ANALYST_FIRM,  inline: true },
        { name: 'Focus',    value: ANALYST_FOCUS, inline: true },
        { name: 'Research', value: health.ready ? `${health.totalChunks} chunks · ${health.sources.length} source(s)` : 'None loaded', inline: false },
        { name: 'Commands', value: '`/ask` — Query framework\n`/analyze <ticker>` — Options analysis\n`/scan` — Earnings catalysts\n`/scalp` — SPX checklist', inline: false },
      )
      .setFooter({ text: 'Powered by Claude AI · Not financial advice' })
      .setTimestamp();
    await interaction.reply({ embeds: [embed] });
  }
});

// ─── Analyst System Prompt ────────────────────────────────────────────────────

function buildAnalystSystem() {
  return `You are ${ANALYST_NAME}, a ${ANALYST_TITLE} at ${ANALYST_FIRM} specializing in ${ANALYST_FOCUS}.

Your frameworks:
- SPX SCALPING (MindEdge v2.0): Session windows 9:30–10:30am / 3–4pm ET only. Multi-timeframe top-down: 10m bias → 3m setup → 30s execution. 9/21 EMA stack. Fibonacci Golden Pocket (0.618–0.65) and OTE (0.705–0.786). GEX mandatory — never trade into a gamma wall. VRVP anchored to session open. BOS/ChoCh structure. Minimum 3 confluences, 6/10 checklist. Stop to breakeven at +8pts, take 50% at +12pts. Max 3 losses then stop.
- OPTIONS SWINGS: Delta 0.50–0.80. IV ideally <50%, hard cap 75%. OI 4000+ preferred, 500 minimum. Daily volume >500 and >20% of OI. ATR >2% of stock price. No calls when RSI >70, no puts when RSI <30. Stop at -25% to -50% of premium. Take first trim at +50%.

Respond as this analyst in first person. Be direct and data-driven. Use **bold** for key points. Keep responses tight — Discord format, no walls of text. Lead with the single most important insight. Be specific about what confirms a setup vs what invalidates it. Always note risk clearly.`;
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max - 3) + '...' : str;
}

// ─── Health Check HTTP Server (keeps Railway happy) ──────────────────────────
import http from 'http';
const PORT = process.env.PORT || 3000;
http.createServer((req, res) => {
  res.writeHead(200);
  res.end(`${ANALYST_NAME} bot is running ✅`);
}).listen(PORT, () => console.log(`🌐 Health check server on port ${PORT}`));

client.on('error', err => console.error('Discord error:', err));
process.on('unhandledRejection', err => console.error('Unhandled rejection:', err));

client.login(process.env.DISCORD_TOKEN);
