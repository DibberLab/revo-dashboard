# Real Avid Analytics Dashboard

A local analytics dashboard pulling live data from Shopify and Klaviyo.

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure credentials
Edit the `.env` file in the project root (already populated with your keys).

### 3. Shopify — Client Credentials Setup
The new Dev Dashboard uses OAuth client credentials (tokens auto-refresh every 24h):

- Go to https://dev.shopify.com/dashboard
- Open your app → **Settings** → copy Client ID + Client Secret into `.env`
- Make sure the app is **installed** on `real-avid.myshopify.com`
- Required scopes: `read_orders`, `read_products`, `read_customers`, `read_analytics`

### 4. Klaviyo API Key
- Go to https://www.klaviyo.com/account#api-keys-tab
- Create or use a Private API Key with read access to: Lists, Campaigns, Flows, Metrics
- Paste into `.env` as `KLAVIYO_API_KEY`

## Run

```bash
npm start
```

Then open: **http://localhost:3000**

## Deploy to DigitalOcean (later)

```bash
# On your droplet:
git clone <repo> && cd real-avid-dashboard
npm install
# Add .env with production keys
# Use PM2 to keep it running:
npm install -g pm2
pm2 start server.js --name real-avid-dashboard
pm2 startup && pm2 save
```
