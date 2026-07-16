require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── Auth ────────────────────────────────────────────────────────────────────
const AUTH_SECRET = process.env.SESSION_SECRET || 'change-me';

function makeToken(email) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(email.toLowerCase()).digest('hex');
}

function getCookies(req) {
  return (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, ...v] = c.trim().split('=');
    if (k) acc[k] = decodeURIComponent(v.join('='));
    return acc;
  }, {});
}

function isAuthed(req) {
  const cookies = getCookies(req);
  const email = cookies['auth_email'] || '';
  if (!email.toLowerCase().endsWith('@revobrands.com')) return false;
  return cookies['auth_token'] === makeToken(email);
}

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login — Revo Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0a0a0a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #161616; border: 1px solid #252525; border-radius: 14px; padding: 40px 36px; width: 360px; max-width: calc(100vw - 32px); }
    .logo { font-size: 20px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; color: #fff; margin-bottom: 4px; }
    .logo span { color: #28a06e; }
    .subtitle { color: #555; font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 32px; }
    label { display: block; font-size: 11px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: #666; margin-bottom: 6px; }
    input[type=email] { display: block; width: 100%; background: #0d0d0d; border: 1px solid #252525; border-radius: 7px; padding: 10px 12px; color: #e0e0e0; font-size: 14px; margin-bottom: 16px; outline: none; transition: border-color .15s; }
    input:focus { border-color: #28a06e; }
    button { width: 100%; background: #28a06e; border: none; border-radius: 7px; padding: 11px; color: #fff; font-size: 14px; font-weight: 700; cursor: pointer; letter-spacing: 0.05em; transition: background .15s; margin-top: 4px; }
    button:hover { background: #1f8a5e; }
    .err { color: #e74c3c; font-size: 13px; margin-bottom: 16px; display: none; }
    .err.show { display: block; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Revo<span>Brands</span></div>
    <div class="subtitle">Analytics Dashboard</div>
    <div class="err" id="err">A Revo Brands email address is required.</div>
    <form method="POST" action="/login">
      <label for="e">Email</label>
      <input type="email" id="e" name="email" autocomplete="email" placeholder="you@revobrands.com" required autofocus>
      <button type="submit">Sign In</button>
    </form>
  </div>
  <script>if (new URLSearchParams(location.search).get('error')) document.getElementById('err').classList.add('show');</script>
</body>
</html>`;

app.get('/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/');
  res.setHeader('Content-Type', 'text/html');
  res.send(LOGIN_PAGE);
});

app.post('/login', (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  if (email.endsWith('@revobrands.com')) {
    const token = makeToken(email);
    res.setHeader('Set-Cookie', [
      `auth_email=${encodeURIComponent(email)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
      `auth_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
    ]);
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'auth_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  res.redirect('/login');
});

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}
app.use(requireAuth);

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

// ─── Brand Configs ─────────────────────────────────────────────────────────────
const BRANDS = {
  ra: {
    shop:         process.env.SHOPIFY_SHOP_RA,
    clientId:     process.env.SHOPIFY_CLIENT_ID_RA,
    clientSecret: process.env.SHOPIFY_CLIENT_SECRET_RA,
    klaviyoKey:   process.env.KLAVIYO_API_KEY_RA,
    _token:       null,
    _tokenExp:    0,
    _metricId:    null,
  },
  wiq: {
    shop:         process.env.SHOPIFY_SHOP_WIQ,
    clientId:     process.env.SHOPIFY_CLIENT_ID_WIQ,
    clientSecret: process.env.SHOPIFY_CLIENT_SECRET_WIQ,
    klaviyoKey:   process.env.KLAVIYO_API_KEY_WIQ,
    _token:       null,
    _tokenExp:    0,
    _metricId:    null,
  },
  oe: {
    shop:         process.env.SHOPIFY_SHOP_OE,
    clientId:     process.env.SHOPIFY_CLIENT_ID_OE,
    clientSecret: process.env.SHOPIFY_CLIENT_SECRET_OE,
    klaviyoKey:   process.env.KLAVIYO_API_KEY_OE,
    _token:       null,
    _tokenExp:    0,
    _metricId:    null,
  },
};

function getBrand(req) {
  return BRANDS[req.query.brand] || BRANDS.ra;
}

// ─── Shopify Token Cache (per brand) ──────────────────────────────────────────
async function getShopifyToken(b) {
  if (b._token && Date.now() < b._tokenExp - 60_000) return b._token;
  const response = await fetch(
    `https://${b.shop}.myshopify.com/admin/oauth/access_token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: b.clientId,
        client_secret: b.clientSecret,
      }),
    }
  );
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Shopify token request failed (${response.status}): ${text}`);
  }
  const { access_token, expires_in } = await response.json();
  b._token   = access_token;
  b._tokenExp = Date.now() + (expires_in || 3600) * 1000;
  return b._token;
}

// ─── Shopify REST (single page) ────────────────────────────────────────────────
async function shopifyREST(b, reqPath) {
  const token = await getShopifyToken(b);
  const response = await fetch(
    `https://${b.shop}.myshopify.com/admin/api/2025-01/${reqPath}`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  if (!response.ok) throw new Error(`REST request failed: ${response.status}`);
  return response.json();
}

// ─── Shopify REST (paginated — follows Link: rel="next" headers) ───────────────
async function shopifyRESTAllPages(b, initialPath, key, retries = 4) {
  const token = await getShopifyToken(b);
  let url = `https://${b.shop}.myshopify.com/admin/api/2025-01/${initialPath}`;
  const allItems = [];
  while (url) {
    let response;
    for (let attempt = 0; attempt <= retries; attempt++) {
      response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      if (response.status === 429 && attempt < retries) {
        const retryAfter = response.headers.get('Retry-After');
        const delay = retryAfter ? parseInt(retryAfter) * 1000 : Math.pow(2, attempt) * 1000;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      break;
    }
    if (!response.ok) throw new Error(`REST request failed: ${response.status}`);
    const data = await response.json();
    allItems.push(...(data[key] || []));
    const link = response.headers.get('Link');
    url = null;
    if (link) {
      const m = link.match(/<([^>]+)>;\s*rel="next"/);
      if (m) url = m[1];
    }
  }
  return allItems;
}

// ─── Klaviyo Helpers (per brand) ──────────────────────────────────────────────
async function klaviyoFetch(b, endpoint, retries = 3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const response = await fetch(`https://a.klaviyo.com/api/${endpoint}`, {
      headers: {
        Authorization: `Klaviyo-API-Key ${b.klaviyoKey}`,
        revision: '2024-10-15',
        Accept: 'application/json',
      },
    });
    if (response.status === 429 && attempt < retries) {
      const retryAfter = response.headers.get('Retry-After');
      const delay = retryAfter ? parseInt(retryAfter) * 1000 : Math.pow(2, attempt) * 1000;
      await new Promise(r => setTimeout(r, delay));
      continue;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Klaviyo request failed (${response.status}): ${text}`);
    }
    return response.json();
  }
}

async function klaviyoPost(b, endpoint, body, retries = 3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const response = await fetch(`https://a.klaviyo.com/api/${endpoint}`, {
      method: 'POST',
      headers: {
        Authorization: `Klaviyo-API-Key ${b.klaviyoKey}`,
        revision: '2024-10-15',
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (response.status === 429 && attempt < retries) {
      const retryAfter = response.headers.get('Retry-After');
      const delay = retryAfter ? parseInt(retryAfter) * 1000 : Math.pow(2, attempt) * 1000;
      await new Promise(r => setTimeout(r, delay));
      continue;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Klaviyo POST failed (${response.status}): ${text}`);
    }
    return response.json();
  }
}

// ─── Timeframe / Date Range Helpers ───────────────────────────────────────────
function getKlaviyoTimeframe(req) {
  if (req.query.start && req.query.end) return { start: req.query.start, end: req.query.end };
  const days = parseInt(req.query.days);
  if (days === 7)  return { key: 'last_7_days' };
  if (days === 30) return { key: 'last_30_days' };
  if (days === 90) return { key: 'last_90_days' };
  return { key: 'last_12_months' };
}

function getShopifyDateRange(req) {
  if (req.query.start && req.query.end) {
    const since = new Date(req.query.start).toISOString();
    const until = new Date(req.query.end + 'T23:59:59').toISOString();
    const days = Math.ceil((new Date(req.query.end) - new Date(req.query.start)) / 86400000) + 1;
    return { since, until, days, isCustom: true, start: req.query.start, end: req.query.end };
  }
  const days = parseInt(req.query.days) || 30;
  const since = new Date(Date.now() - days * 86400000).toISOString();
  return { since, until: null, days, isCustom: false };
}

function getComparisonDateRange(current, compareType) {
  if (!compareType || compareType === 'none') return null;
  if (compareType === 'period') {
    const sinceMs = new Date(current.since).getTime();
    const untilMs = current.until ? new Date(current.until).getTime() : Date.now();
    const dur = untilMs - sinceMs;
    const compSince = new Date(sinceMs - dur);
    const compUntil = new Date(sinceMs);
    return {
      since: compSince.toISOString(),
      until: compUntil.toISOString(),
      days: current.days,
      isCustom: true,
      start: compSince.toISOString().split('T')[0],
      end:   compUntil.toISOString().split('T')[0],
    };
  }
  if (compareType === 'year') {
    const s = new Date(current.since);
    s.setFullYear(s.getFullYear() - 1);
    // For rolling periods current.until is null — treat the effective end as now
    const effectiveUntilMs = current.until ? new Date(current.until).getTime() : Date.now();
    const u = new Date(effectiveUntilMs);
    u.setFullYear(u.getFullYear() - 1);
    return {
      since: s.toISOString(),
      until: u.toISOString(),
      days: current.days,
      isCustom: current.isCustom,
      start: s.toISOString().split('T')[0],
      end:   u.toISOString().split('T')[0],
    };
  }
  return null;
}

// ─── Core Shopify Summary Computation ─────────────────────────────────────────
async function computeShopifySummary(b, { since, until, days, isCustom, start, end }) {
  let orderPath = `orders.json?status=any&created_at_min=${since}&limit=250&fields=id,subtotal_price,financial_status,created_at,customer`;
  let checkoutPath = `checkouts.json?status=open&created_at_min=${since}&limit=250&fields=id,created_at`;
  if (until) {
    orderPath    += `&created_at_max=${until}`;
    checkoutPath += `&created_at_max=${until}`;
  }

  const [orders, abandoned] = await Promise.all([
    shopifyRESTAllPages(b, orderPath, 'orders'),
    shopifyRESTAllPages(b, checkoutPath, 'checkouts').catch(() => []),
  ]);

  const paidOrders = orders.filter(o => ['paid', 'partially_paid'].includes(o.financial_status));
  const totalRevenue = paidOrders.reduce((sum, o) => sum + parseFloat(o.subtotal_price || 0), 0);
  const orderCount   = paidOrders.length;
  const aov          = orderCount > 0 ? totalRevenue / orderCount : 0;
  const totalCheckouts   = orderCount + abandoned.length;
  const checkoutConvRate = totalCheckouts > 0 ? (orderCount / totalCheckouts) * 100 : null;
  const newCustomerOrders       = paidOrders.filter(o => o.customer?.created_at && o.customer.created_at >= since).length;
  const returningCustomerOrders = orderCount - newCustomerOrders;
  const returningRate = orderCount > 0 ? (returningCustomerOrders / orderCount) * 100 : 0;

  const startDate = start || since.split('T')[0];
  const endDate   = end   || (until ? until.split('T')[0] : new Date().toISOString().split('T')[0]);
  const dailyMap  = {};
  for (let d = new Date(startDate); ; d.setDate(d.getDate() + 1)) {
    const key = d.toISOString().split('T')[0];
    dailyMap[key] = { date: key, revenue: 0, orders: 0, abandoned: 0, newCustomers: 0 };
    if (key >= endDate) break;
  }
  paidOrders.forEach(o => {
    const key = o.created_at.split('T')[0];
    if (dailyMap[key]) {
      dailyMap[key].revenue += parseFloat(o.subtotal_price || 0);
      dailyMap[key].orders  += 1;
      if (o.customer?.created_at && o.customer.created_at >= since) dailyMap[key].newCustomers += 1;
    }
  });
  abandoned.forEach(c => {
    const key = c.created_at.split('T')[0];
    if (dailyMap[key]) dailyMap[key].abandoned += 1;
  });
  Object.values(dailyMap).forEach(d => {
    d.aov = d.orders > 0 ? parseFloat((d.revenue / d.orders).toFixed(2)) : 0;
    const tot = d.orders + d.abandoned;
    d.checkoutConvRate = tot > 0
      ? parseFloat(((d.orders / tot) * 100).toFixed(1))
      : null;
  });

  return {
    totalRevenue: parseFloat(totalRevenue.toFixed(2)),
    orderCount,
    aov:                parseFloat(aov.toFixed(2)),
    checkoutConvRate:   checkoutConvRate !== null ? parseFloat(checkoutConvRate.toFixed(1)) : null,
    newCustomerOrders,
    returningCustomerOrders,
    returningRate:      parseFloat(returningRate.toFixed(1)),
    dailyData:          Object.values(dailyMap),
    days,
  };
}

// ─── API Routes ────────────────────────────────────────────────────────────────

app.get('/api/health', async (req, res) => {
  const b = getBrand(req);
  const results = { shopify: false, klaviyo: false, errors: {} };
  try {
    await getShopifyToken(b);
    results.shopify = true;
  } catch (e) { results.errors.shopify = e.message; }
  try {
    await klaviyoFetch(b, 'accounts/');
    results.klaviyo = true;
  } catch (e) {
    if (e.message.includes('429')) results.klaviyo = true;
    else results.errors.klaviyo = e.message;
  }
  res.json(results);
});

// Shopify summary with optional period/YoY comparison
app.get('/api/shopify/summary', async (req, res) => {
  try {
    const b          = getBrand(req);
    const range       = getShopifyDateRange(req);
    const compareType = req.query.compare;
    const compRange   = getComparisonDateRange(range, compareType);

    const current    = await computeShopifySummary(b, range);
    const comparison = compRange ? await computeShopifySummary(b, compRange) : null;

    res.json({
      ...current,
      comparison: comparison
        ? { ...comparison, start: compRange.start, end: compRange.end }
        : null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function fetchTopProducts(b, since, until, limit = 15) {
  let orderPath = `orders.json?status=any&created_at_min=${since}&limit=250&financial_status=paid&fields=line_items`;
  if (until) orderPath += `&created_at_max=${until}`;
  const orders = await shopifyRESTAllPages(b, orderPath, 'orders');
  const productMap = {};
  orders.forEach(order => {
    (order.line_items || []).forEach(item => {
      const key = item.product_id;
      if (!productMap[key]) productMap[key] = { id: key, title: item.title, quantity: 0, revenue: 0 };
      productMap[key].quantity += item.quantity;
      productMap[key].revenue  += parseFloat(item.price) * item.quantity;
    });
  });
  return Object.values(productMap)
    .sort((a, b) => b.revenue - a.revenue)
    .slice(0, limit)
    .map(p => ({ ...p, revenue: parseFloat(p.revenue.toFixed(2)), aov: p.quantity > 0 ? parseFloat((p.revenue / p.quantity).toFixed(2)) : 0 }));
}

app.get('/api/shopify/top-products', async (req, res) => {
  try {
    const b           = getBrand(req);
    const range       = getShopifyDateRange(req);
    const compareType = req.query.compare;
    const compRange   = getComparisonDateRange(range, compareType);

    const products = await fetchTopProducts(b, range.since, range.until);

    let comparison = null;
    if (compRange) {
      const compProducts = await fetchTopProducts(b, compRange.since, compRange.until, 50);
      const compMap = {};
      compProducts.forEach(p => { compMap[p.id] = p; });
      comparison = {
        products: products.map(p => compMap[p.id] || { id: p.id, title: p.title, quantity: 0, revenue: 0, aov: 0 }),
        start: compRange.start,
        end: compRange.end,
      };
    }

    res.json({ products, comparison });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/shopify/recent-orders', async (req, res) => {
  try {
    const b = getBrand(req);
    const data = await shopifyREST(b,
      `orders.json?status=any&limit=20&fields=id,name,total_price,financial_status,fulfillment_status,created_at,customer,line_items`
    );
    res.json({ orders: data.orders || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/email/overview', async (req, res) => {
  try {
    const b = getBrand(req);
    const [accountData, listsData] = await Promise.all([
      klaviyoFetch(b, 'accounts/'),
      klaviyoFetch(b, 'lists/?fields[list]=name,created,updated'),
    ]);
    const account  = accountData.data?.[0] || {};
    const rawLists = listsData.data || [];
    const lists = await Promise.all(rawLists.map(async l => {
      let profileCount = 0;
      try {
        const pd = await klaviyoFetch(b, `lists/${l.id}/profiles/?page[size]=1&fields[profile]=id`);
        profileCount = pd?.meta?.total || 0;
        if (!profileCount && pd?.data?.length > 0) profileCount = '1+';
      } catch (e) { /* ignore */ }
      return { id: l.id, name: l.attributes?.name, profileCount, updated: l.attributes?.updated };
    }));
    res.json({
      accountName: account.attributes?.contact_information?.default_sender_name || '',
      lists: lists.sort((a, bb) => (bb.profileCount || 0) - (a.profileCount || 0)),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function getPlacedOrderMetricId(b) {
  if (b._metricId) return b._metricId;
  try {
    const data = await klaviyoFetch(b, 'metrics/');
    const metric = (data.data || []).find(m =>
      m.attributes?.name === 'Placed Order' || m.attributes?.name === 'Ordered Product'
    );
    if (metric) b._metricId = metric.id;
  } catch (e) { console.error('Could not fetch metric ID:', e.message); }
  return b._metricId;
}

app.get('/api/email/campaigns', async (req, res) => {
  try {
    const b = getBrand(req);
    const campaignsData = await klaviyoFetch(b,
      "campaigns/?filter=and(equals(messages.channel,'email'),equals(status,'Sent'))&sort=-scheduled_at&fields[campaign]=name,status,created_at,send_time"
    );
    const campaigns = (campaignsData.data || []).map(c => ({
      id: c.id,
      name: c.attributes?.name,
      status: c.attributes?.status,
      createdAt: c.attributes?.created_at,
      sendTime: c.attributes?.send_time,
    }));

    const metricId = await getPlacedOrderMetricId(b);
    let statsMap = {};
    if (metricId && campaigns.length > 0) {
      try {
        const reportBody = {
          data: {
            type: 'campaign-values-report',
            attributes: {
              timeframe: getKlaviyoTimeframe(req),
              conversion_metric_id: metricId,
              statistics: ['recipients', 'opens_unique', 'open_rate', 'clicks_unique', 'click_rate', 'conversion_value'],
              group_by: ['campaign_id', 'campaign_message_id'],
            },
          },
        };
        const reportData = await klaviyoPost(b, 'campaign-values-reports/', reportBody);
        (reportData?.data?.attributes?.results || []).forEach(r => {
          const cid = r.groupings?.campaign_id;
          if (!cid) return;
          const s = r.statistics || {};
          if (!statsMap[cid]) statsMap[cid] = { recipients: 0, opens_unique: 0, clicks_unique: 0, conversion_value: 0 };
          statsMap[cid].recipients       += s.recipients       || 0;
          statsMap[cid].opens_unique     += s.opens_unique     || 0;
          statsMap[cid].clicks_unique    += s.clicks_unique    || 0;
          statsMap[cid].conversion_value += s.conversion_value || 0;
        });
        Object.values(statsMap).forEach(s => {
          s.open_rate  = s.recipients > 0 ? s.opens_unique  / s.recipients : 0;
          s.click_rate = s.recipients > 0 ? s.clicks_unique / s.recipients : 0;
        });
      } catch (e) { console.error('Campaign report error:', e.message); }
    }

    const enriched = campaigns.map(c => ({
      ...c,
      recipients:   statsMap[c.id]?.recipients       || 0,
      opensUnique:  statsMap[c.id]?.opens_unique      || 0,
      openRate:     statsMap[c.id]?.open_rate         || 0,
      clicksUnique: statsMap[c.id]?.clicks_unique     || 0,
      clickRate:    statsMap[c.id]?.click_rate        || 0,
      revenue:      statsMap[c.id]?.conversion_value  || 0,
    }));

    res.json({ campaigns: enriched, metricId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/email/flows', async (req, res) => {
  try {
    const b = getBrand(req);
    const flowsData = await klaviyoFetch(b,
      "flows/?filter=equals(status,'live')&fields[flow]=name,status,created,updated&sort=-updated"
    );
    const flows = (flowsData.data || []).map(f => ({
      id: f.id,
      name: f.attributes?.name,
      status: f.attributes?.status,
      updated: f.attributes?.updated,
      created: f.attributes?.created,
    }));

    const metricId = await getPlacedOrderMetricId(b);
    let statsMap = {};
    if (metricId && flows.length > 0) {
      try {
        const reportBody = {
          data: {
            type: 'flow-values-report',
            attributes: {
              timeframe: getKlaviyoTimeframe(req),
              conversion_metric_id: metricId,
              statistics: ['conversion_value', 'recipients', 'opens_unique', 'clicks_unique'],
              group_by: ['flow_id', 'flow_message_id'],
            },
          },
        };
        const reportData = await klaviyoPost(b, 'flow-values-reports/', reportBody);
        (reportData?.data?.attributes?.results || []).forEach(r => {
          const fid = r.groupings?.flow_id;
          if (!fid) return;
          const s = r.statistics || {};
          if (!statsMap[fid]) statsMap[fid] = { conversion_value: 0, recipients: 0, opens_unique: 0, clicks_unique: 0 };
          statsMap[fid].conversion_value += s.conversion_value || 0;
          statsMap[fid].recipients       += s.recipients       || 0;
          statsMap[fid].opens_unique     += s.opens_unique     || 0;
          statsMap[fid].clicks_unique    += s.clicks_unique    || 0;
        });
      } catch (e) { console.error('Flow report error:', e.message); }
    }

    const enriched = flows.map(f => ({
      ...f,
      revenue:    statsMap[f.id]?.conversion_value || 0,
      recipients: statsMap[f.id]?.recipients       || 0,
    }));

    res.json({ flows: enriched });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/email/top-products', async (req, res) => {
  try {
    const b = getBrand(req);

    // Find all "Ordered Product" metric IDs (fires once per line item, has Name/Quantity/$value)
    if (!b._orderedProductIds) {
      const metricsData = await klaviyoFetch(b, 'metrics/');
      b._orderedProductIds = (metricsData.data || [])
        .filter(m => m.attributes?.name === 'Ordered Product')
        .map(m => m.id);
    }
    const metricIds = b._orderedProductIds;
    if (!metricIds.length) return res.json({ products: [] });

    // Build ISO date range
    let since, until;
    if (req.query.start && req.query.end) {
      since = new Date(req.query.start + 'T00:00:00Z').toISOString();
      until = new Date(req.query.end   + 'T23:59:59Z').toISOString();
    } else {
      const days = parseInt(req.query.days) || 30;
      since = new Date(Date.now() - days * 86400000).toISOString();
      until = new Date().toISOString();
    }

    const productMap = {};
    const MAX_PAGES = 5; // 500 events per metric

    for (const metricId of metricIds) {
      let cursor = null;
      let pageCount = 0;
      do {
        let url = `events?filter=and(equals(metric_id,'${metricId}'),greater-or-equal(datetime,'${since}'),less-or-equal(datetime,'${until}'))` +
                  `&fields[event]=event_properties&page[size]=100&sort=-datetime`;
        if (cursor) url += `&page[cursor]=${encodeURIComponent(cursor)}`;

        const data = await klaviyoFetch(b, url);
        for (const event of (data.data || [])) {
          const props = event.attributes?.event_properties || {};
          const name = props.Name || props.ProductName || props.Title || 'Unknown';
          if (name === 'Unknown') continue;
          const qty = Number(props.Quantity) || 1;
          const rev = Number(props['$value']) || 0;
          const key = name.toLowerCase();
          if (!productMap[key]) productMap[key] = { title: name, quantity: 0, revenue: 0 };
          productMap[key].quantity += qty;
          productMap[key].revenue  += rev;
        }

        cursor = null;
        if (data.links?.next) {
          try { cursor = new URL(data.links.next).searchParams.get('page[cursor]'); } catch {}
        }
        pageCount++;
      } while (cursor && pageCount < MAX_PAGES);
    }

    const products = Object.values(productMap)
      .sort((a, bb) => bb.revenue - a.revenue)
      .map(p => ({ ...p, aov: p.quantity > 0 ? p.revenue / p.quantity : 0 }));

    res.json({ products });
  } catch (e) {
    console.error('Email top products error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/shopify/analytics', (req, res) => {
  res.json({ daily: [], available: false });
});

// ─── Google Analytics 4 ───────────────────────────────────────────────────────

const GA4_PROPERTIES = {
  ra:  process.env.GA4_PROPERTY_RA,
  wiq: process.env.GA4_PROPERTY_WIQ,
  oe:  process.env.GA4_PROPERTY_OE,
};

let _ga4Creds = null;
function getGA4Creds() {
  if (!_ga4Creds) {
    const credPath = path.join(__dirname, 'data', 'ga4-credentials.json');
    _ga4Creds = JSON.parse(fs.readFileSync(credPath, 'utf8'));
  }
  return _ga4Creds;
}

let _ga4Token = null, _ga4TokenExp = 0;
async function getGA4Token() {
  if (_ga4Token && Date.now() < _ga4TokenExp - 60_000) return _ga4Token;
  const creds = getGA4Creds();
  const now = Math.floor(Date.now() / 1000);
  const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss:   creds.client_email,
    scope: 'https://www.googleapis.com/auth/analytics.readonly',
    aud:   'https://oauth2.googleapis.com/token',
    iat:   now,
    exp:   now + 3600,
  })).toString('base64url');
  const sigInput = `${header}.${payload}`;
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(sigInput);
  const sig = sign.sign(creds.private_key, 'base64url');
  const jwt = `${sigInput}.${sig}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const { access_token, expires_in, error } = await resp.json();
  if (!access_token) throw new Error(`GA4 token error: ${error}`);
  _ga4Token = access_token;
  _ga4TokenExp = Date.now() + (expires_in || 3600) * 1000;
  return _ga4Token;
}

async function fetchGA4Sessions(propertyId, startDate, endDate) {
  const token = await getGA4Token();
  const resp = await fetch(
    `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`,
    {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dateRanges: [{ startDate, endDate }],
        dimensions: [{ name: 'date' }],
        metrics:    [{ name: 'sessions' }],
        orderBys:   [{ dimension: { dimensionName: 'date' } }],
      }),
    }
  );
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`GA4 API ${resp.status}: ${txt.slice(0, 200)}`);
  }
  const data = await resp.json();
  const rows = data.rows || [];
  const daily = rows.map(r => ({
    date:     r.dimensionValues[0].value.replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'),
    sessions: parseInt(r.metricValues[0].value, 10) || 0,
  }));
  const totalSessions = daily.reduce((s, d) => s + d.sessions, 0);
  return { daily, totalSessions };
}

app.get('/api/ga4/sessions', async (req, res) => {
  try {
    const rawBrand = Array.isArray(req.query.brand) ? req.query.brand[0] : (req.query.brand || 'ra');
    const brandKey = rawBrand.replace(/[^a-z0-9]/gi, '');
    const propertyId = GA4_PROPERTIES[brandKey];
    if (!propertyId) return res.json({ error: 'No GA4 property configured for this brand' });

    const dateRange = getShopifyDateRange(req);
    const startDate = dateRange.start || dateRange.since.split('T')[0];
    const endDate   = dateRange.end   || (dateRange.until ? dateRange.until.split('T')[0] : new Date().toISOString().split('T')[0]);

    const current = await fetchGA4Sessions(propertyId, startDate, endDate);

    let comparison = null;
    const compareType = req.query.compare;
    if (compareType && compareType !== 'none') {
      const compRange = getComparisonDateRange(dateRange, compareType);
      if (compRange) {
        comparison = await fetchGA4Sessions(propertyId, compRange.start, compRange.end);
        comparison.start = compRange.start;
        comparison.end   = compRange.end;
      }
    }

    res.json({ ...current, comparison });
  } catch (e) {
    console.error('GA4 sessions error:', e.message);
    res.json({ error: e.message, daily: [], totalSessions: 0, comparison: null });
  }
});

// ─── Meta Ads (CSV-backed) ────────────────────────────────────────────────────
const ADS_DATA_DIR = path.join(__dirname, 'data');

function adsFilePath(brand) {
  return path.join(ADS_DATA_DIR, `${brand}-ads.json`);
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; }
    else if (ch === ',' && !inQuotes) { result.push(current.trim()); current = ''; }
    else { current += ch; }
  }
  result.push(current.trim());
  return result;
}

function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return [];
  const headers = parseCSVLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    if (values.length < 2) continue;
    const row = {};
    headers.forEach((h, idx) => { row[h] = values[idx] !== undefined ? values[idx] : ''; });
    rows.push(row);
  }
  return rows;
}

function adsRowKey(row) {
  return `${normalizeDate(row['Day'])}||${row['Campaign name']}||${row['Ad set name']}||${row['Ad name']}`;
}

function loadAdsRows(brand) {
  try {
    const f = adsFilePath(brand);
    if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch (_) {}
  return [];
}

function saveAdsRows(brand, rows) {
  if (!fs.existsSync(ADS_DATA_DIR)) fs.mkdirSync(ADS_DATA_DIR, { recursive: true });
  fs.writeFileSync(adsFilePath(brand), JSON.stringify(rows), 'utf8');
}

function parseNum(v) {
  if (!v || v === '--' || v === 'N/A') return 0;
  return parseFloat(String(v).replace(/[$,%]/g, '')) || 0;
}

function normalizeDate(dateStr) {
  if (!dateStr) return dateStr;
  const parts = dateStr.split('/');
  if (parts.length !== 3) return dateStr;
  const [m, d, y] = parts;
  const year = y.length === 2 ? '20' + y : y;
  return `${year}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
}

function aggregateAds(rows) {
  const dailyMap    = {};
  const campaignMap = {};
  const adsetMap    = {};
  const adMap       = {};
  let totalSpend = 0, totalRevenue = 0, totalPurchases = 0;
  let totalClicks = 0, totalImpressions = 0, totalReach = 0;

  for (const row of rows) {
    const spend       = parseNum(row['Amount spent (USD)']);
    const revenue     = parseNum(row['Purchases conversion value']);
    const purchases   = parseNum(row['Purchases']);
    const clicks      = parseNum(row['Clicks (all)']);
    const impressions = parseNum(row['Impressions']);
    const reach       = parseNum(row['Reach']);

    totalSpend       += spend;
    totalRevenue     += revenue;
    totalPurchases   += purchases;
    totalClicks      += clicks;
    totalImpressions += impressions;
    totalReach       += reach;

    const dateKey = normalizeDate(row['Day']);
    if (!dailyMap[dateKey]) dailyMap[dateKey] = { date: dateKey, spend: 0, revenue: 0, purchases: 0, clicks: 0, impressions: 0 };
    dailyMap[dateKey].spend       += spend;
    dailyMap[dateKey].revenue     += revenue;
    dailyMap[dateKey].purchases   += purchases;
    dailyMap[dateKey].clicks      += clicks;
    dailyMap[dateKey].impressions += impressions;

    const camp = row['Campaign name'] || 'Unknown';
    if (!campaignMap[camp]) campaignMap[camp] = { name: camp, spend: 0, revenue: 0, purchases: 0, clicks: 0, lastDate: null };
    campaignMap[camp].spend     += spend;
    campaignMap[camp].revenue   += revenue;
    campaignMap[camp].purchases += purchases;
    campaignMap[camp].clicks    += clicks;
    if (!campaignMap[camp].lastDate || dateKey > campaignMap[camp].lastDate) campaignMap[camp].lastDate = dateKey;

    const adset = row['Ad set name'] || 'Unknown';
    if (!adsetMap[adset]) adsetMap[adset] = { name: adset, campaign: camp, spend: 0, revenue: 0, purchases: 0, clicks: 0 };
    adsetMap[adset].spend     += spend;
    adsetMap[adset].revenue   += revenue;
    adsetMap[adset].purchases += purchases;
    adsetMap[adset].clicks    += clicks;

    const adName = row['Ad name'] || 'Unknown';
    if (!adMap[adName]) adMap[adName] = { name: adName, adset, spend: 0, revenue: 0, purchases: 0, clicks: 0 };
    adMap[adName].spend     += spend;
    adMap[adName].revenue   += revenue;
    adMap[adName].purchases += purchases;
    adMap[adName].clicks    += clicks;
  }

  const daily = Object.values(dailyMap).sort((a, b) => a.date.localeCompare(b.date));
  daily.forEach(d => { d.roas = d.spend > 0 ? +(d.revenue / d.spend).toFixed(3) : 0; });

  const withRoas = arr => arr
    .map(c => ({ ...c, roas: c.spend > 0 ? +(c.revenue / c.spend).toFixed(3) : 0, cpc: c.clicks > 0 ? +(c.spend / c.clicks).toFixed(3) : 0 }))
    .sort((a, b) => b.spend - a.spend);

  return {
    totals: {
      spend:           +totalSpend.toFixed(2),
      revenue:         +totalRevenue.toFixed(2),
      roas:            totalSpend > 0 ? +(totalRevenue / totalSpend).toFixed(3) : 0,
      purchases:       Math.round(totalPurchases),
      clicks:          Math.round(totalClicks),
      impressions:     Math.round(totalImpressions),
      reach:           Math.round(totalReach),
      avgCpc:          totalClicks > 0 ? +(totalSpend / totalClicks).toFixed(3) : 0,
      costPerPurchase: totalPurchases > 0 ? +(totalSpend / totalPurchases).toFixed(2) : 0,
    },
    daily,
    campaigns: withRoas(Object.values(campaignMap)),
    adsets:    withRoas(Object.values(adsetMap)),
    ads:       withRoas(Object.values(adMap)),
    rowCount:  rows.length,
  };
}

app.get('/api/ads/data', (req, res) => {
  try {
    const brand = (req.query.brand || 'wiq').replace(/[^a-z0-9]/gi, '');
    const allRows = loadAdsRows(brand);
    if (allRows.length === 0) return res.json({ totals: null, daily: [], campaigns: [], adsets: [], ads: [], rowCount: 0 });

    const emptyTotals = { spend:0,revenue:0,roas:0,purchases:0,clicks:0,impressions:0,reach:0,avgCpc:0,costPerPurchase:0 };

    let startDate = null, endDate = null, currentRange = null;
    if (req.query.start && req.query.end) {
      startDate = req.query.start;
      endDate   = req.query.end;
      currentRange = { since: startDate + 'T00:00:00Z', until: endDate + 'T23:59:59Z', days: null, isCustom: true, start: startDate, end: endDate };
    } else if (req.query.days) {
      const days = parseInt(req.query.days);
      const now  = new Date();
      endDate    = now.toISOString().split('T')[0];
      startDate  = new Date(now - days * 86400000).toISOString().split('T')[0];
      currentRange = { since: new Date(now - days * 86400000).toISOString(), until: now.toISOString(), days, isCustom: false, start: startDate, end: endDate };
    }

    const filterRows = (rows, s, e) => rows.filter(r => { const d = normalizeDate(r['Day']); return d >= s && d <= e; });
    const rows = (startDate && endDate) ? filterRows(allRows, startDate, endDate) : allRows;
    if (rows.length === 0) return res.json({ totals: emptyTotals, daily: [], campaigns: [], adsets: [], ads: [], rowCount: 0 });

    const result = aggregateAds(rows);

    const compareType = req.query.compare;
    if (compareType && compareType !== 'none' && currentRange) {
      const compRange = getComparisonDateRange(currentRange, compareType);
      if (compRange) {
        const compRows = filterRows(allRows, compRange.start, compRange.end);
        result.comparison = compRows.length > 0
          ? { ...aggregateAds(compRows), start: compRange.start, end: compRange.end }
          : { totals: emptyTotals, daily: [], campaigns: [], adsets: [], ads: [], rowCount: 0, start: compRange.start, end: compRange.end };
      }
    }

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/ads/upload', express.text({ limit: '20mb', type: '*/*' }), (req, res) => {
  try {
    const brand = (req.query.brand || 'wiq').replace(/[^a-z0-9]/gi, '');
    const newRows = parseCSV(req.body || '');
    const existing = loadAdsRows(brand);
    const existingKeys = new Set(existing.map(adsRowKey));
    let added = 0;
    for (const row of newRows) {
      const key = adsRowKey(row);
      if (!existingKeys.has(key)) {
        existing.push(row);
        existingKeys.add(key);
        added++;
      }
    }
    saveAdsRows(brand, existing);
    res.json({ success: true, added, total: existing.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── LoyaltyLion (Elite Rewards — Real Avid only) ─────────────────────────────
// LoyaltyLion's public API has no aggregate reporting endpoint — only paginated
// List Customers / List Transactions, and this program has 300k+ customer records
// (LoyaltyLion mirrors the full Shopify customer base, not just enrolled members).
// A full crawl takes many minutes, so it can only ever happen once: results are
// persisted to disk with a per-resource high-water mark, and every refresh after
// the first is an incremental `updated_at_min` / `created_at_min` sync — merged
// into the on-disk store — rather than a re-crawl of the whole account.
const LL_BASE = 'https://api.loyaltylion.com/v2';
const LL_PERIODS = [7, 30, 90, 365];
const LL_TRANSACTION_LOOKBACK_DAYS = 400; // covers the 365-day bucket with margin
const LL_SYNC_OVERLAP_MS = 5 * 60 * 1000; // re-check a 5 min window each sync to absorb API eventual-consistency lag
const LL_STORE_FILE = path.join(__dirname, 'data', 'loyaltylion-store.json');

async function loyaltyLionFetch(reqPath, params = {}, retries = 3) {
  const url = new URL(`${LL_BASE}/${reqPath}`);
  Object.entries(params).forEach(([k, v]) => { if (v != null) url.searchParams.set(k, v); });
  for (let attempt = 0; attempt <= retries; attempt++) {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${process.env.LL_KEY}`, Accept: 'application/json' },
    });
    if (response.status === 429 && attempt < retries) {
      const retryAfter = response.headers.get('Retry-After');
      const delay = retryAfter ? parseInt(retryAfter) * 1000 : Math.pow(2, attempt) * 1000;
      await new Promise(r => setTimeout(r, delay));
      continue;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`LoyaltyLion request failed (${response.status}): ${text}`);
    }
    return response.json();
  }
}

const llProgress = { customers: 0, transactions: 0 };

async function loyaltyLionAllPages(reqPath, key, params = {}) {
  const items = [];
  let cursor = null;
  let page = 0;
  const t0 = Date.now();
  llProgress[key] = 0;
  do {
    const body = await loyaltyLionFetch(reqPath, { ...params, limit: 500, cursor });
    items.push(...(body[key] || []));
    cursor = body.cursor?.next || null;
    page++;
    if (page % 10 === 0) {
      console.log(`LoyaltyLion ${key}: page ${page}, ${items.length} so far (${((Date.now() - t0) / 1000).toFixed(0)}s elapsed)`);
    }
    llProgress[key] = items.length;
  } while (cursor);
  console.log(`LoyaltyLion ${key}: done — ${items.length} fetched in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
  return items;
}

function loadLLStore() {
  try {
    const raw = JSON.parse(fs.readFileSync(LL_STORE_FILE, 'utf8'));
    return {
      customers: raw.customers || {},
      transactions: raw.transactions || [],
      lastCustomerSync: raw.lastCustomerSync || null,
      lastTransactionSync: raw.lastTransactionSync || null,
    };
  } catch {
    return { customers: {}, transactions: [], lastCustomerSync: null, lastTransactionSync: null };
  }
}

function saveLLStore(store) {
  fs.writeFileSync(LL_STORE_FILE, JSON.stringify(store));
}

const llStore = loadLLStore();

// Upserts changed/new customers (minimized to just the fields KPIs need) into the store.
async function syncLoyaltyLionCustomers(store) {
  const params = store.lastCustomerSync
    ? { updated_at_min: new Date(new Date(store.lastCustomerSync).getTime() - LL_SYNC_OVERLAP_MS).toISOString() }
    : {};
  const syncStart = new Date().toISOString();
  const fetched = await loyaltyLionAllPages('customers', 'customers', params);
  fetched.forEach(c => {
    store.customers[c.id] = {
      enrolled: !!c.enrolled,
      enrolled_at: c.enrolled_at || null,
      tier: c.loyalty_tier_membership?.loyalty_tier?.name || null,
      points: c.points_approved || 0,
      referredBy: c.referred_by?.id || null,
      email: c.email || null,
      segment: c.insights_segment || null,
      rewardsClaimed: c.rewards_claimed || 0,
    };
  });
  store.lastCustomerSync = syncStart;
  return fetched.length;
}

// Transactions are immutable, so a sync only ever appends; old entries outside
// the lookback window are trimmed so the store doesn't grow without bound.
async function syncLoyaltyLionTransactions(store) {
  const params = {
    created_at_min: store.lastTransactionSync
      ? new Date(new Date(store.lastTransactionSync).getTime() - LL_SYNC_OVERLAP_MS).toISOString()
      : new Date(Date.now() - LL_TRANSACTION_LOOKBACK_DAYS * 86400000).toISOString(),
  };
  const syncStart = new Date().toISOString();
  const fetched = await loyaltyLionAllPages('transactions', 'transactions', params);
  const seenIds = new Set(store.transactions.map(t => t.id));
  let added = 0;
  fetched.forEach(t => {
    if (seenIds.has(t.id)) return;
    seenIds.add(t.id);
    added++;
    store.transactions.push({
      id: t.id,
      created_at: t.created_at,
      resource: t.resource,
      points_approved: t.points_approved || 0,
      rewardTitle: t.resource === 'claimed_reward' ? (t.claimed_reward?.reward?.title || 'Reward') : null,
      customerId: t.customer?.id ?? null,
    });
  });
  const cutoff = Date.now() - LL_TRANSACTION_LOOKBACK_DAYS * 86400000;
  store.transactions = store.transactions.filter(t => new Date(t.created_at).getTime() >= cutoff);
  store.lastTransactionSync = syncStart;
  return added;
}

function computeLoyaltyLionSummaryFromStore(store) {
  const now = Date.now();
  const customersById = store.customers;
  const customers = Object.values(customersById);
  const transactions = store.transactions;
  const enrolled = customers.filter(c => c.enrolled);
  const enrolledMembers = enrolled.length;

  // Tier breakdown (+ avg outstanding points per tier)
  const tierAgg = {};
  enrolled.forEach(c => {
    const name = c.tier || 'No Tier';
    if (!tierAgg[name]) tierAgg[name] = { count: 0, points: 0 };
    tierAgg[name].count++;
    tierAgg[name].points += c.points || 0;
  });
  const tierBreakdown = Object.entries(tierAgg)
    .map(([name, v]) => ({ name, count: v.count, avgPoints: v.count > 0 ? Math.round(v.points / v.count) : 0 }))
    .sort((a, b) => b.count - a.count);

  // Points liability (outstanding, redeemable balance across enrolled members)
  const totalPointsOutstanding = enrolled.reduce((s, c) => s + (c.points || 0), 0);
  const avgPointsPerMember = enrolledMembers > 0 ? Math.round(totalPointsOutstanding / enrolledMembers) : 0;

  // Referral program — counted across all synced customers, not just enrolled,
  // since referral participation doesn't require loyalty enrollment.
  const referredMembers = customers.filter(c => c.referredBy).length;
  const referrerCounts = {};
  customers.forEach(c => {
    if (!c.referredBy) return;
    referrerCounts[c.referredBy] = (referrerCounts[c.referredBy] || 0) + 1;
  });
  const topReferrers = Object.entries(referrerCounts)
    .map(([id, count]) => ({ email: customersById[id]?.email || `Customer #${id}`, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // LoyaltyLion's own insights segments (At Risk / Win Back / Loyal / etc.)
  const segmentCounts = {};
  enrolled.forEach(c => {
    const seg = c.segment || 'Unclassified';
    segmentCounts[seg] = (segmentCounts[seg] || 0) + 1;
  });
  const segmentBreakdown = Object.entries(segmentCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  // Repeat redemption rate — lifetime, via the customer's own rewards_claimed counter
  // (more accurate than the transaction window, which only covers the trailing 400 days)
  const redeemers = enrolled.filter(c => (c.rewardsClaimed || 0) > 0);
  const repeatRedeemers = enrolled.filter(c => (c.rewardsClaimed || 0) >= 2);
  const repeatRedemptionRate = redeemers.length > 0 ? (repeatRedeemers.length / redeemers.length) * 100 : 0;

  const rewardCounts = {};
  const periods = {};
  const longestPeriod = LL_PERIODS[LL_PERIODS.length - 1];
  LL_PERIODS.forEach(days => {
    const cutoff = now - days * 86400000;
    const newMembers = customers.filter(c => c.enrolled_at && new Date(c.enrolled_at).getTime() >= cutoff).length;
    let pointsIssued = 0, pointsRedeemed = 0, rewardsClaimed = 0;
    const tierRedemptionAgg = {};
    transactions.forEach(t => {
      if (new Date(t.created_at).getTime() < cutoff) return;
      if (t.resource === 'claimed_reward') {
        const amt = Math.abs(t.points_approved || 0);
        pointsRedeemed += amt;
        rewardsClaimed += 1;
        const tierName = (t.customerId != null && customersById[t.customerId]?.tier) || 'No Tier';
        if (!tierRedemptionAgg[tierName]) tierRedemptionAgg[tierName] = { rewardsClaimed: 0, pointsRedeemed: 0 };
        tierRedemptionAgg[tierName].rewardsClaimed += 1;
        tierRedemptionAgg[tierName].pointsRedeemed += amt;
        if (days === longestPeriod) {
          rewardCounts[t.rewardTitle || 'Reward'] = (rewardCounts[t.rewardTitle || 'Reward'] || 0) + 1;
        }
      } else if ((t.points_approved || 0) > 0) {
        pointsIssued += t.points_approved;
      }
    });
    const tierRedemptions = Object.entries(tierRedemptionAgg)
      .map(([name, v]) => ({ name, rewardsClaimed: v.rewardsClaimed, pointsRedeemed: v.pointsRedeemed }))
      .sort((a, b) => b.rewardsClaimed - a.rewardsClaimed);
    periods[days] = { newMembers, pointsIssued, pointsRedeemed, rewardsClaimed, tierRedemptions };
  });

  const topRewards = Object.entries(rewardCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return {
    totalMembers: customers.length,
    enrolledMembers,
    tierBreakdown,
    totalPointsOutstanding,
    avgPointsPerMember,
    referredMembers,
    topReferrers,
    segmentBreakdown,
    repeatRedemptionRate,
    redeemersCount: redeemers.length,
    repeatRedeemersCount: repeatRedeemers.length,
    periods,
    topRewards,
  };
}

// Customers and transactions are synced on independent schedules. Transactions
// are a true incremental append (proven: a 20-min cycle re-fetched only a
// handful of records) so they can refresh often. Customers can't be made cheap
// the same way — LoyaltyLion (or the underlying Shopify sync) touches
// `updated_at` on a large fraction of the ~470k customer roster within any
// short window, so an `updated_at_min` sync there still re-pages a huge chunk
// of the account. Member/tier counts don't need to be fresher than a few times
// a day for a dashboard, so that expensive sync just runs far less often.
const LL_TRANSACTION_SYNC_INTERVAL_MS = 15 * 60 * 1000; // 15 min
const LL_CUSTOMER_SYNC_INTERVAL_MS = 12 * 60 * 60 * 1000; // 12 hours

let llCache = { data: null, computedAt: 0, error: null };
let llCustomersSyncing = false;
let llTransactionsSyncing = false;
let llCustomersSyncedAt = null;
let llTransactionsSyncedAt = null;

function recomputeLLCache() {
  try {
    llCache = { data: computeLoyaltyLionSummaryFromStore(llStore), computedAt: Date.now(), error: null };
  } catch (e) {
    console.error('LoyaltyLion compute error:', e.message);
    llCache.error = e.message;
  }
}

async function refreshLoyaltyLionCustomers() {
  if (llCustomersSyncing || !process.env.LL_KEY) return;
  llCustomersSyncing = true;
  try {
    const isFirstSync = !llStore.lastCustomerSync;
    const added = await syncLoyaltyLionCustomers(llStore);
    saveLLStore(llStore);
    llCustomersSyncedAt = Date.now();
    recomputeLLCache();
    console.log(`LoyaltyLion customers ${isFirstSync ? 'initial backfill' : 'sync'} complete: +${added} (${Object.keys(llStore.customers).length} total)`);
  } catch (e) {
    console.error('LoyaltyLion customer sync error:', e.message);
    llCache.error = e.message;
  } finally {
    llCustomersSyncing = false;
  }
}

async function refreshLoyaltyLionTransactions() {
  if (llTransactionsSyncing || !process.env.LL_KEY) return;
  llTransactionsSyncing = true;
  try {
    const isFirstSync = !llStore.lastTransactionSync;
    const added = await syncLoyaltyLionTransactions(llStore);
    saveLLStore(llStore);
    llTransactionsSyncedAt = Date.now();
    recomputeLLCache();
    console.log(`LoyaltyLion transactions ${isFirstSync ? 'initial backfill' : 'sync'} complete: +${added} (${llStore.transactions.length} in window)`);
  } catch (e) {
    console.error('LoyaltyLion transaction sync error:', e.message);
    llCache.error = e.message;
  } finally {
    llTransactionsSyncing = false;
  }
}

if (process.env.LL_KEY) {
  refreshLoyaltyLionCustomers();
  refreshLoyaltyLionTransactions();
  setInterval(refreshLoyaltyLionCustomers, LL_CUSTOMER_SYNC_INTERVAL_MS);
  setInterval(refreshLoyaltyLionTransactions, LL_TRANSACTION_SYNC_INTERVAL_MS);
}

app.get('/api/loyaltylion/summary', (req, res) => {
  if (!process.env.LL_KEY) return res.status(404).json({ error: 'LoyaltyLion is not configured' });
  if (!llCache.data) {
    if (llCache.error) return res.status(502).json({ error: llCache.error });
    return res.json({ loading: true, progress: llProgress });
  }
  res.json({
    ...llCache.data,
    computedAt: llCache.computedAt,
    customersSyncedAt: llCustomersSyncedAt,
    transactionsSyncedAt: llTransactionsSyncedAt,
  });
});

// ─── Claude Insights ──────────────────────────────────────────────────────────
function sfmt(n) {
  if (!n) return '$0';
  if (n >= 1000000) return '$' + (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000)    return '$' + (n / 1000).toFixed(1) + 'K';
  return '$' + n.toFixed(0);
}
function nfmt(n) {
  if (!n) return '0';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000)    return (n / 1000).toFixed(1) + 'K';
  return String(Math.round(n));
}
function pctChange(a, b) {
  if (!b) return '';
  const p = ((a - b) / Math.abs(b) * 100).toFixed(1);
  return ` (${p >= 0 ? '+' : ''}${p}% vs prior)`;
}

function sfmtP(v, prefix) {
  if (prefix === '$') return sfmt(v || 0);
  if (prefix === 'x') return (v || 0).toFixed(2) + 'x';
  return nfmt(v || 0);
}

function buildModalPrompt(brandName, dateRange, modal) {
  const lines = [];

  if (modal.type === 'timeseries') {
    const values = modal.values || [];
    const isoLabels = modal.isoLabels || [];
    const prefix = modal.prefix || '';
    const valid = values.filter(v => v != null && !isNaN(v));
    const total = valid.reduce((a, b) => a + b, 0);
    const avg   = valid.length > 0 ? total / valid.length : 0;
    const max   = valid.length > 0 ? Math.max(...valid) : 0;
    const min   = valid.length > 0 ? Math.min(...valid) : 0;
    const mid   = Math.floor(valid.length / 2);
    const h1avg = mid > 0 ? valid.slice(0, mid).reduce((a, b) => a + b, 0) / mid : 0;
    const h2avg = (valid.length - mid) > 0 ? valid.slice(mid).reduce((a, b) => a + b, 0) / (valid.length - mid) : 0;
    const trend = h2avg > h1avg * 1.08 ? 'accelerating ↑' : h2avg < h1avg * 0.92 ? 'decelerating ↓' : 'steady';

    lines.push(`You are a sharp e-commerce data analyst. Review this specific chart data for ${brandName} (${dateRange}) and write exactly 2 short paragraphs of insights.`);
    lines.push(`Requirements: surface non-obvious trends or anomalies, reference specific numbers, suggest one concrete action per paragraph. Be direct.`);
    lines.push('');
    lines.push(`── ${(modal.title || '').toUpperCase()} ──`);
    if (prefix !== 'x') {
      lines.push(`Total: ${sfmtP(total, prefix)} | Daily avg: ${sfmtP(avg, prefix)} | Max: ${sfmtP(max, prefix)} | Min: ${sfmtP(min, prefix)}`);
    } else {
      lines.push(`Avg: ${sfmtP(avg, prefix)} | Max: ${sfmtP(max, prefix)} | Min: ${sfmtP(min, prefix)}`);
    }
    lines.push(`Trend: ${trend} (first-half avg ${sfmtP(h1avg, prefix)}/day → second-half avg ${sfmtP(h2avg, prefix)}/day)`);
    if (isoLabels.length > 0) {
      const n = Math.min(14, isoLabels.length);
      const recent = isoLabels.slice(-n).map((d, i) => `${d}: ${sfmtP(values[values.length - n + i], prefix)}`);
      lines.push(`Recent ${n} days: ${recent.join(' | ')}`);
    }
    if (modal.compValues && modal.compLabel) {
      const cv = modal.compValues.filter(v => v != null && !isNaN(v));
      const ct = cv.reduce((a, b) => a + b, 0);
      const ca = cv.length > 0 ? ct / cv.length : 0;
      lines.push(prefix !== 'x'
        ? `Prior period (${modal.compLabel}): Total ${sfmtP(ct, prefix)} | Avg ${sfmtP(ca, prefix)}/day`
        : `Prior period (${modal.compLabel}): Avg ${sfmtP(ca, prefix)}`);
    }
  }

  else if (modal.type === 'bar-campaigns') {
    const items = modal.items || [];
    const totalRev = items.reduce((s, c) => s + (c.revenue || 0), 0);
    const opens    = items.filter(c => c.openRate);
    const clicks   = items.filter(c => c.clickRate);
    const avgOpen  = opens.length  > 0 ? opens.reduce((s, c) => s + c.openRate, 0)  / opens.length  : 0;
    const avgClick = clicks.length > 0 ? clicks.reduce((s, c) => s + c.clickRate, 0) / clicks.length : 0;

    lines.push(`You are a sharp e-commerce data analyst. Review this Klaviyo campaign data for ${brandName} (${dateRange}) and write exactly 2 short paragraphs of insights.`);
    lines.push(`Requirements: identify best/worst performers, surface non-obvious patterns, reference specific numbers, suggest one concrete action per paragraph. Be direct.`);
    lines.push('');
    lines.push('── CAMPAIGN REVENUE ──');
    lines.push(`Total: ${sfmt(totalRev)} across ${items.length} campaigns | Avg open: ${(avgOpen * 100).toFixed(1)}% | Avg click: ${(avgClick * 100).toFixed(1)}%`);
    lines.push('Campaigns:');
    items.forEach(c => {
      const parts = [`  ${c.name}:`, sfmt(c.revenue || 0) + ' rev'];
      if (c.openRate)   parts.push((c.openRate  * 100).toFixed(1) + '% open');
      if (c.clickRate)  parts.push((c.clickRate * 100).toFixed(1) + '% click');
      if (c.recipients) parts.push(nfmt(c.recipients) + ' rcpt');
      lines.push(parts.join(' | '));
    });
  }

  else if (modal.type === 'bar-flows') {
    const items    = modal.items || [];
    const totalRev = items.reduce((s, f) => s + (f.revenue || 0), 0);

    lines.push(`You are a sharp e-commerce data analyst. Review this Klaviyo flow data for ${brandName} (${dateRange}) and write exactly 2 short paragraphs of insights.`);
    lines.push(`Requirements: identify revenue concentration, underperforming flows, reference specific numbers, suggest one concrete action per paragraph. Be direct.`);
    lines.push('');
    lines.push('── FLOW REVENUE ──');
    lines.push(`Total flow revenue: ${sfmt(totalRev)} across ${items.length} flows`);
    lines.push('Flows:');
    items.forEach(f => {
      const pct  = totalRev > 0 ? ((f.revenue || 0) / totalRev * 100).toFixed(1) : '0.0';
      const parts = [`  ${f.name}:`, sfmt(f.revenue || 0), pct + '% of total'];
      if (f.recipients) parts.push(nfmt(f.recipients) + ' rcpt');
      lines.push(parts.join(' | '));
    });
  }

  else {
    lines.push(`You are a sharp e-commerce data analyst. Review this chart data for ${brandName} (${dateRange}) and write 2 short paragraphs of insights. Be direct and data-driven.`);
  }

  return lines.join('\n');
}

function buildDataContext(shopify, klaviyo, ads, loyaltylion, dateRange) {
  const lines = [];
  const today = new Date().toISOString().split('T')[0];

  // Fix 4 — data freshness header so Claude knows this is retrospective analysis
  lines.push(`Data window: ${dateRange || 'unknown'} | Report generated: ${today}`);
  lines.push('');

  if (shopify) {
    const s = shopify, c = s.comp;
    lines.push('── SHOPIFY ──');
    lines.push(`Net Sales: ${sfmt(s.revenue)}${c ? pctChange(s.revenue, c.revenue) : ''}`);
    lines.push(`Orders: ${nfmt(s.orders)}${c ? pctChange(s.orders, c.orders) : ''}`);
    lines.push(`AOV: ${sfmt(s.aov)}${c ? pctChange(s.aov, c.aov) : ''}`);
    lines.push(`New Customers: ${nfmt(s.newCustomers)}${c ? pctChange(s.newCustomers, c.newCustomers) : ''}`);
    lines.push(`Returning Rate: ${s.returningRate?.toFixed(1)}%${c ? ` (was ${c.returningRate?.toFixed(1)}%)` : ''}`);
    if (s.checkoutConvRate != null) lines.push(`Checkout Completion Rate: ${s.checkoutConvRate?.toFixed(1)}%`);
    if (s.dailyData?.length > 1) {
      const valid      = s.dailyData.filter(d => d.revenue != null);
      const mid        = Math.floor(valid.length / 2);
      const h1         = valid.slice(0, mid).reduce((a, b) => a + b.revenue, 0) / (mid || 1);
      const h2         = valid.slice(mid).reduce((a, b) => a + b.revenue, 0) / ((valid.length - mid) || 1);
      const trend      = h2 > h1 * 1.08 ? 'accelerating' : h2 < h1 * 0.92 ? 'decelerating' : 'steady';
      const peak       = valid.reduce((a, b) => b.revenue > a.revenue ? b : a, valid[0]);
      const low        = valid.reduce((a, b) => b.revenue < a.revenue ? b : a, valid[0]);
      // Fix 3 — anchor trend to explicit date ranges, not just "first half / second half"
      const winStart   = valid[0].date;
      const winEnd     = valid[valid.length - 1].date;
      const h1End      = valid[mid - 1]?.date || winStart;
      const h2Start    = valid[mid]?.date || winEnd;
      lines.push(`Revenue trend: ${trend} | Window: ${winStart} to ${winEnd}`);
      lines.push(`  First half (${winStart}–${h1End}): avg ${sfmt(h1)}/day → Second half (${h2Start}–${winEnd}): avg ${sfmt(h2)}/day`);
      lines.push(`Peak: ${peak.date} ${sfmt(peak.revenue)} | Lowest: ${low.date} ${sfmt(low.revenue)}`);
    }
    if (s.topProducts?.length > 0) {
      lines.push('Top products: ' + s.topProducts.slice(0, 6).map((p, i) => `${i + 1}. ${p.title} ${sfmt(p.revenue)}`).join(' | '));
    }
    lines.push('');
  }

  if (klaviyo) {
    const k = klaviyo;
    lines.push('── EMAIL (KLAVIYO) ──');
    lines.push(`Total revenue: ${sfmt(k.emailRevenue)} | Campaigns: ${k.campaignCount} | Active flows: ${k.activeFlows}`);
    lines.push(`Avg recipients/campaign: ${nfmt(k.avgRecipients)}`);
    if (k.campaigns?.length > 0) {
      lines.push('Campaigns:');
      k.campaigns.slice(0, 8).forEach(c => {
        const parts = [`  ${c.name}:`, sfmt(c.revenue || 0) + ' rev'];
        if (c.openRate)   parts.push((c.openRate  * 100).toFixed(1) + '% open');
        if (c.clickRate)  parts.push((c.clickRate * 100).toFixed(1) + '% click');
        if (c.recipients) parts.push(nfmt(c.recipients) + ' rcpt');
        // Fix 2 — include send date so Claude knows whether campaigns are recent or historical
        if (c.sendTime)   parts.push('sent: ' + c.sendTime.split('T')[0]);
        lines.push(parts.join(' | '));
      });
    }
    if (k.flows?.length > 0) {
      lines.push('Flows: ' + k.flows.slice(0, 6).map(f => `${f.name} ${sfmt(f.revenue || 0)}`).join(' | '));
    }
    lines.push('');
  }

  if (ads) {
    const a = ads;
    lines.push('── META ADS ──');
    // Fix 1 — explicit date range + historical warning so Claude doesn't recommend acting on finished campaigns
    if (a.adsStart && a.adsEnd) {
      lines.push(`Data covers ${a.adsStart} to ${a.adsEnd} — this is historical CSV data. Campaigns may no longer be active.`);
    }
    lines.push(`Spend: ${sfmt(a.spend)} | Revenue: ${sfmt(a.revenue)} | ROAS: ${a.roas?.toFixed(2)}x`);
    lines.push(`Purchases: ${nfmt(a.purchases)} | Cost/purchase: ${sfmt(a.costPerPurchase)} | CPC: ${sfmt(a.avgCpc)}`);
    lines.push(`Clicks: ${nfmt(a.clicks)} | Impressions: ${nfmt(a.impressions)}`);
    if (a.campaigns?.length > 0) {
      lines.push('By campaign:');
      a.campaigns.slice(0, 8).forEach(c =>
        lines.push(`  ${c.name}: ${sfmt(c.spend)} spend | ${c.roas?.toFixed(2)}x ROAS | ${nfmt(c.purchases || 0)} purchases | ${sfmt(c.cpc)} CPC`)
      );
    }
    if (a.dailyRecent?.length > 1) {
      const mid  = Math.floor(a.dailyRecent.length / 2);
      const h1r  = a.dailyRecent.slice(0, mid).reduce((s, d) => s + d.roas, 0) / (mid || 1);
      const h2r  = a.dailyRecent.slice(mid).reduce((s, d) => s + d.roas, 0) / ((a.dailyRecent.length - mid) || 1);
      const dStart = a.dailyRecent[0].date;
      const dEnd   = a.dailyRecent[a.dailyRecent.length - 1].date;
      lines.push(`ROAS trend: ${h1r.toFixed(2)}x → ${h2r.toFixed(2)}x (${dStart} to ${dEnd})`);
    }
    lines.push('');
  }

  if (loyaltylion) {
    const l = loyaltylion;
    lines.push('── ELITE REWARDS (LOYALTYLION) ──');
    lines.push(`Enrolled members: ${nfmt(l.enrolledMembers)} of ${nfmt(l.totalMembers)} total customers`);
    lines.push(`New enrollees: ${nfmt(l.newMembers)} | Points issued: ${nfmt(l.pointsIssued)} | Points redeemed: ${nfmt(l.pointsRedeemed)} | Rewards claimed: ${nfmt(l.rewardsClaimed)}`);
    lines.push(`Points liability (outstanding): ${nfmt(l.totalPointsOutstanding)} | Avg per member: ${nfmt(l.avgPointsPerMember)}`);
    lines.push(`Referred members: ${nfmt(l.referredMembers)} | Repeat redemption rate: ${l.repeatRedemptionRate?.toFixed(1)}% (${nfmt(l.repeatRedeemersCount)} of ${nfmt(l.redeemersCount)} redeemers)`);
    if (l.tierBreakdown?.length > 0) {
      lines.push('Tier breakdown: ' + l.tierBreakdown.map(t => `${t.name}: ${nfmt(t.count)} (avg ${nfmt(t.avgPoints)} pts)`).join(' | '));
    }
    if (l.tierRedemptions?.length > 0) {
      lines.push('Redemption by tier: ' + l.tierRedemptions.map(t => `${t.name}: ${nfmt(t.rewardsClaimed)} claims, ${nfmt(t.pointsRedeemed)} pts`).join(' | '));
    }
    if (l.segmentBreakdown?.length > 0) {
      lines.push('Member segments: ' + l.segmentBreakdown.map(s => `${s.name}: ${nfmt(s.count)}`).join(' | '));
    }
    if (l.topReferrers?.length > 0) {
      lines.push('Top referrers: ' + l.topReferrers.slice(0, 5).map(r => `${r.email} (${r.count})`).join(' | '));
    }
    if (l.topRewards?.length > 0) {
      lines.push('Top claimed rewards (12mo): ' + l.topRewards.slice(0, 6).map(r => `${r.name} (${r.count})`).join(' | '));
    }
  }

  return lines.join('\n');
}

function buildInsightsPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion) {
  const isWIQ = brandName === 'Work IQ Tools';
  const dataCtx = buildDataContext(shopify, klaviyo, ads, loyaltylion, dateRange);
  const tail = `Write exactly 2 short paragraphs. Reference specific numbers, surface non-obvious correlations, flag anything that needs immediate attention, and end each paragraph with one concrete action. Be direct. Do not restate obvious facts.`;

  let intro;

  if (tab === 'shopify') {
    // All brands: pure Shopify metrics only — no email, no ads
    intro = [
      `You are a sharp e-commerce analyst. Review the ${brandName} Shopify sales data for ${dateRange}.`,
      `Focus your analysis on:`,
      `1. Revenue trends — daily patterns, peaks, dips, and what's driving them`,
      `2. Order volume, AOV, and any shifts in purchase behavior`,
      `3. New vs. returning customer mix and what it implies about acquisition vs. retention`,
      `4. Checkout completion rate and any friction signals`,
      ``,
      tail,
    ];
  } else if (tab === 'klaviyo') {
    // All brands: email/Klaviyo only — no ads, no broad Shopify analysis
    intro = [
      `You are a sharp email marketing analyst. Review the ${brandName} Klaviyo data for ${dateRange}.`,
      `Focus your analysis on:`,
      `1. Campaign performance — which sends drove the most revenue, and why (open rate, list size, timing)`,
      `2. Flow revenue — which automated flows are the strongest performers and which are underperforming`,
      `3. Engagement health — open rate and click rate trends and what they imply about list quality`,
      `4. Any campaigns or flows that stand out as anomalies (unusually high or low performance)`,
      ``,
      tail,
    ];
  } else if (tab === 'eliterewards') {
    // Real Avid Elite Rewards (LoyaltyLion) tab: loyalty program only
    intro = [
      `You are a sharp loyalty/retention analyst. Review the Real Avid Elite Rewards (LoyaltyLion) data for ${dateRange}.`,
      `Focus your analysis on:`,
      `1. Enrollment momentum — how new enrollees this period compares to the enrolled member base`,
      `2. Points economy health — points issued vs. redeemed, outstanding points liability, and what it implies about engagement vs. financial exposure`,
      `3. Tier and segment dynamics — how redemption and member counts break down across tiers, and what the At Risk/Win Back/Loyal segment mix suggests about retention priorities`,
      `4. Referral and repeat-redemption behavior — how much of the member base is referral-driven, and whether redeemers tend to come back for more`,
      ``,
      tail,
    ];
  } else if (tab === 'ads') {
    // WIQ Meta Ads tab: ads only — no email
    intro = [
      `You are a sharp performance marketing analyst. Review the Work IQ Tools Meta Ads data for ${dateRange}.`,
      `IMPORTANT: This is historical CSV data. The campaigns shown may already be paused or finished. Do not recommend pausing, scaling, or restarting specific campaigns — focus on what the data reveals about performance patterns and what to apply going forward.`,
      `Focus your analysis on:`,
      `1. ROAS trends — which campaigns delivered profitable returns vs. burned budget, and what drove the difference`,
      `2. Cost efficiency — CPC and cost-per-purchase trends across the window`,
      `3. Spend vs. revenue relationship — did spend increases translate to proportional revenue?`,
      `4. Patterns or learnings worth applying to future campaigns`,
      ``,
      tail,
    ];
  } else if (tab === 'overview' && isWIQ) {
    // WIQ Overview: cross-channel view — both email AND Meta Ads impact on overall revenue
    intro = [
      `You are a sharp performance marketing analyst. Review the Work IQ Tools dashboard for ${dateRange}.`,
      `Focus your analysis on:`,
      `1. The combined impact of Meta Ads and email on total Shopify revenue — which channel is driving more and at what cost`,
      `2. Meta Ads efficiency this period — ROAS, cost-per-purchase, and any trends worth flagging`,
      `3. Email contribution — which campaigns or flows had measurable impact on sales`,
      `4. Any cross-channel signals or anomalies (e.g. spend up but revenue flat, email revenue spiking without a campaign)`,
      ``,
      tail,
    ];
  } else {
    // RA / OE Overview (and any other tab): email impact on sales
    intro = [
      `You are a sharp e-commerce analyst specializing in email marketing attribution. Review the ${brandName} dashboard data for ${dateRange}.`,
      `Focus your analysis on:`,
      `1. The relationship between email campaigns/flows and Shopify sales — look for revenue spikes that align with campaign send dates and quantify the lift`,
      `2. Email's share of total revenue — which campaigns and flows had the highest measurable impact on sales`,
      `3. Engagement health signals — open rate and click rate trends and what they imply about list quality or content resonance`,
      `4. Any non-obvious correlations or anomalies worth flagging`,
      ``,
      tail,
    ];
  }

  return [...intro, '', dataCtx].join('\n');
}

function buildChatSystemPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion) {
  return [
    `You are a concise data analyst assistant for ${brandName}. The user is viewing their analytics dashboard for ${dateRange}.`,
    `Answer questions directly using specific numbers from the data. Keep responses brief (2-4 sentences) unless a detailed breakdown is explicitly requested. Do not add unnecessary caveats or disclaimers.`,
    '',
    'Current dashboard data:',
    '',
    buildDataContext(shopify, klaviyo, ads, loyaltylion, dateRange),
  ].join('\n');
}

app.post('/api/insights', express.json({ limit: '1mb' }), async (req, res) => {
  try {
    const { brand, tab, dateRange, shopify, klaviyo, ads, loyaltylion, modal } = req.body;
    const brandNames = { ra: 'Real Avid', wiq: 'Work IQ Tools', oe: 'Outdoor Edge' };
    const brandName  = brandNames[brand] || brand;

    const prompt = (tab === 'modal' && modal)
      ? buildModalPrompt(brandName, dateRange, modal)
      : buildInsightsPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion);

    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 750,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!claudeRes.ok) {
      const errText = await claudeRes.text();
      throw new Error(`Claude API ${claudeRes.status}: ${errText}`);
    }
    const claudeData = await claudeRes.json();
    res.json({ insights: claudeData.content[0]?.text || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const TAB_LAYOUTS = {
  overview: `KPI row 1 (Shopify/GA4): Revenue, Orders, AOV, Sessions, Conversion Rate (orders/sessions)
KPI row 2 (Klaviyo): Email List Size, Active Subscribers
Sparkline charts: Revenue, Orders, AOV, Sessions, Conv Rate
Email Revenue sparkline, Top Products mini bar chart
Klaviyo Campaign Revenue bar chart, Flow Revenue bar chart
WIQ only — Meta Ads section: Spend, Revenue, ROAS, Cost/Purchase KPIs + 4 sparkline charts`,

  shopify: `KPI row: Net Sales, Orders, AOV, New Customers, Returning Rate %, Checkout Completion %, Sessions (GA4), Conv Rate (orders/sessions)
8 sparkline chart panels (one per KPI, all clickable to open detail modal with daily table + comparison)
Top Products table: Title, Revenue, Orders, AOV, % of total revenue`,

  klaviyo: `KPI row: Avg Recipients/Campaign, Campaigns Sent, Active Flows, Email Revenue
Campaigns table: Name, Revenue, Recipients, Open Rate, Click Rate, Send Date (sortable)
Flows table: Name, Revenue, Open Rate, Click Rate, Emails Sent
No charts for individual campaigns — only aggregate KPIs`,

  ads: `KPI row: Total Spend, Revenue, ROAS, Purchases, Clicks, CPC, Impressions, Cost/Purchase
8 sparkline chart panels (one per KPI, all clickable to detail modal)
Campaign Performance table: Campaign, Spend, Revenue, ROAS, Purchases, Clicks, CPC
Ad Set Performance table: Ad Set, Campaign, Spend, Revenue, ROAS, Purchases, Clicks, CPC
Ad Performance table: Ad Name, Ad Set, Spend, Revenue, ROAS, Purchases, Clicks, CPC
Data source: uploaded Meta Ads CSV export`,

  eliterewards: `KPI row 1 (period toggle: 7D/30D/90D/1Y, not the global date picker): Enrolled Members, New Enrollees, Points Issued, Points Redeemed, Rewards Claimed
KPI row 2 (lifetime/current snapshot, not period-scoped): Points Liability (outstanding), Avg Points/Member, Referred Members, Repeat Redemption Rate
Tier Breakdown table: Tier, Members, % of Enrolled, Avg Points
Redemption by Tier table (period-scoped): Tier, Rewards Claimed, Points Redeemed
Member Insights Segments table: Segment (At Risk/Win Back/Loyal/etc.), Members, % of Enrolled
Top Referrers table: Referrer, Members Referred
Top Claimed Rewards table (trailing 12mo): Reward, Times Claimed
Data source: LoyaltyLion API (Customers + Transactions) — customers synced ~every 12h (large account, ~470k records), transactions synced ~every 15 min — Real Avid only, no per-brand comparison`,
};

function buildDevFeedbackPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion) {
  const layout = TAB_LAYOUTS[tab] || `${tab} tab`;
  const dataCtx = buildDataContext(shopify, klaviyo, ads, loyaltylion, dateRange);
  return [
    `You are a dashboard UX/analytics consultant reviewing a multi-brand e-commerce analytics dashboard for ${brandName}.`,
    `The developer who built this dashboard is asking for your honest critique and suggestions.`,
    ``,
    `DATE RANGE: ${dateRange}`,
    ``,
    `CURRENT "${tab.toUpperCase()}" TAB LAYOUT:`,
    layout,
    ``,
    `CURRENT DATA SNAPSHOT:`,
    dataCtx || '(no data loaded)',
    ``,
    `Give exactly 4–5 numbered suggestions tailored to this specific tab and data. Address:`,
    `• Missing KPIs or metrics that would meaningfully improve business decisions`,
    `• Better chart types or data relationships (scatter, cohort, funnel, etc.)`,
    `• Layout/UX improvements (grouping, ordering, drill-down patterns)`,
    `• Cross-metric views or correlations worth surfacing`,
    ``,
    `Be specific and actionable — name the exact metric, chart type, or implementation. Reference actual numbers from the data where they inform your suggestions. Skip generic best-practices platitudes.`,
  ].join('\n');
}

app.post('/api/devfeedback', express.json({ limit: '1mb' }), async (req, res) => {
  try {
    const { brand, tab, dateRange, shopify, klaviyo, ads, loyaltylion } = req.body;
    const brandNames = { ra: 'Real Avid', wiq: 'Work IQ Tools', oe: 'Outdoor Edge' };
    const brandName  = brandNames[brand] || brand;
    const prompt = buildDevFeedbackPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion);

    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 600,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!claudeRes.ok) {
      const errText = await claudeRes.text();
      throw new Error(`Claude API ${claudeRes.status}: ${errText}`);
    }
    const claudeData = await claudeRes.json();
    res.json({ feedback: claudeData.content[0]?.text || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/chat', express.json({ limit: '2mb' }), async (req, res) => {
  try {
    const { brand, tab, dateRange, shopify, klaviyo, ads, loyaltylion, modal, messages } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'No messages provided' });
    }
    const brandNames = { ra: 'Real Avid', wiq: 'Work IQ Tools', oe: 'Outdoor Edge' };
    const brandName  = brandNames[brand] || brand;

    const { insightText } = req.body;

    let system;
    if (tab === 'modal' && modal) {
      const base = buildModalPrompt(brandName, dateRange, modal)
        .replace(/write exactly 2 short paragraphs.*?Be direct\./s,
          'Answer questions directly using specific numbers from the data. Keep responses brief (2-4 sentences) unless a detailed breakdown is requested.');
      system = insightText
        ? base + `\n\nYou previously provided this analysis:\n${insightText}\n\nContinue the discussion, staying grounded in both the data and your prior analysis.`
        : base;
    } else {
      system = buildChatSystemPrompt(brandName, tab, dateRange, shopify, klaviyo, ads, loyaltylion);
      if (insightText) {
        system += `\n\nYou previously provided the following analysis of this data:\n${insightText}\n\nThe user wants to follow up. Keep your responses grounded in the data and your prior analysis.`;
      }
    }

    const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 600,
        system,
        messages,
      }),
    });

    if (!claudeRes.ok) {
      const errText = await claudeRes.text();
      throw new Error(`Claude API ${claudeRes.status}: ${errText}`);
    }
    const claudeData = await claudeRes.json();
    res.json({ reply: claudeData.content?.[0]?.text || '' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎯 Analytics Dashboard`);
  console.log(`   Running at: http://localhost:${PORT}`);
  console.log(`   Press Ctrl+C to stop\n`);
});
