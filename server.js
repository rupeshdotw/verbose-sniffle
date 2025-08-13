import express from "express";
import puppeteer from "puppeteer-core";
import { config as dotenv } from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import helmet, { referrerPolicy } from "helmet";
import rateLimit from "express-rate-limit";
import os from 'os';
import session from 'express-session';
import * as connectRedis from 'connect-redis';
import { createClient } from 'redis';
import https from 'https';
import fs from 'fs/promises';
import pool from './db.js';
import bcrypt from 'bcrypt';

dotenv();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Add body parsing middleware for JSON and URL-encoded forms
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.APP_PORT;

// resolution stats
const resolutionStats = {
  success: 0,
  successUrls: [],
  failure: 0,
  perRegion: {},
  failedUrls: [], // ⬅️ new array to collect failed URLs
};

//Reset Resolution Stat data in every 24hours
function resetStats() {
resolutionStats.success = 0;
resolutionStats.failure = 0;
resolutionStats.perRegion = {};
resolutionStats.failedUrls = [];
console.log("📊 Resolution stats have been reset");
}
// Time of day to reset (24-hour format)
const RESET_HOUR = 0;  // 3 AM
const RESET_MINUTE = 0;
const RESET_SECOND = 0;

// Calculate the delay until the next reset time
function getDelayUntilNextReset() {
  const now = new Date();
  const nextReset = new Date();
  nextReset.setHours(RESET_HOUR, RESET_MINUTE, RESET_SECOND, 0);
  if (nextReset <= now) {
    // If the time today has already passed, schedule for tomorrow
    nextReset.setDate(nextReset.getDate() + 1);
  }
  return nextReset - now;
}

setTimeout(() => {
  // Run once at the specified time
  resetStats();

  // Then schedule it to run every 24 hours
  setInterval(resetStats, 24 * 60 * 60 * 1000);

}, getDelayUntilNextReset());

// Define authentication configuration
// const authConfig = {
//   users: { 'admin': 'Admin@quick10' },
//   challenge: true,
//   realm: 'Private Area',
//   unauthorizedResponse: req => '🚫 Unauthorized Access',
// };

// Apply Basic Authentication to multiple routes
// app.use('/', basicAuth(authConfig));
//app.use('/resolve', basicAuth(authConfig));
// app.use('/analytics', basicAuth(authConfig));
//app.use('/resolve-multiple', basicAuth(authConfig));

// Setup Redis client
const RedisStore = connectRedis.default(session); // 👈 use .default

const redisClient = createClient({
  url: process.env.REDIS_URL,
  legacyMode: true, // Important for compatibility
});

await redisClient.connect().catch(console.error);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));


// Restrictive access control: only admins can access anything except index.html, login, register, and auth pages
app.use((req, res, next) => {
  const publicPaths = ['/', '/index.html', '/login', '/register', '/auth/login.html', '/auth/register.html', '/auth/error.html'];
  const isPublic =
    publicPaths.includes(req.path) ||
    req.path.startsWith('/public/') ||
    req.path.startsWith('/style.css') ||
    req.path.startsWith('/app.js') ||
    req.path.startsWith('/favicon.ico');
  if (isPublic) return next();
  if (req.session && req.session.user) {
    if (req.session.user.role === 'admin') {
      return next(); // Admins can access everything
    } else {
      // Non-admins: only allow public pages
      return res.redirect('/index.html');
    }
  }
  // Not logged in: redirect to login
  if (req.accepts('html')) {
    return res.redirect('/auth/login.html');
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// Enhanced middleware stack
app.use(helmet({
  contentSecurityPolicy: false, // Enable and customize as needed
  referrerPolicy : {
    policy: "no-referrer",
  },
})); // Security headers

// Enable CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : null;

if (!allowedOrigins) {
  console.error('[CORS] ERROR: ALLOWED_ORIGINS environment variable is not set.');
  process.exit(1); // Or handle it another way, like disabling CORS
}
console.log('[CORS] Allowed origins:', allowedOrigins);

app.use(cors({
  origin: '*',
  credentials: false
}));
// app.use(cors({
//   origin: function (origin, callback) {
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   credentials: false
// }));
// End CORS setup

app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: process.env.RATE_LIMIT || 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
if (process.env.ENABLE_RATE_LIMIT !== 'false') {
  console.log('[Rate Limiting] ENABLED');
  app.use('/resolve', limiter);
} else {
  console.log('[Rate Limiting] DISABLED');
}

app.set('trust proxy', 1);

// Activity Logging Middleware Example
function logActivity(action, details = '') {
  return async (req, res, next) => {
    if (req.session.user) {
      await pool.query(
        'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
        [req.session.user.id, action, details]
      );
    }
    next();
  };
}

// Role-based access middleware
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// BRIGHTDATA_API_USAGE_CONFIG
const API_KEY = process.env.BRIGHTDATA_API_KEY;
const ZONE = process.env.BRIGHTDATA_ZONE;

// Region to proxy zone mapping
const regionZoneMap = {
  US: process.env.BRIGHTDATA_US_PROXY,
  CA: process.env.BRIGHTDATA_CA_PROXY,
  GB: process.env.BRIGHTDATA_GB_PROXY,
  IN: process.env.BRIGHTDATA_IN_PROXY,
  AU: process.env.BRIGHTDATA_AU_PROXY,
  DE: process.env.BRIGHTDATA_DE_PROXY,
  FR: process.env.BRIGHTDATA_FR_PROXY,
  JP: process.env.BRIGHTDATA_JP_PROXY,
  SG: process.env.BRIGHTDATA_SG_PROXY,
  BR: process.env.BRIGHTDATA_BR_PROXY,
  TW: process.env.BRIGHTDATA_TW_PROXY,
  CZ: process.env.BRIGHTDATA_CZ_PROXY,
  UA: process.env.BRIGHTDATA_UA_PROXY,
  AE: process.env.BRIGHTDATA_AE_PROXY,
  PL: process.env.BRIGHTDATA_PL_PROXY,
  ES: process.env.BRIGHTDATA_ES_PROXY,
  ID: process.env.BRIGHTDATA_ID_PROXY,
  ZA: process.env.BRIGHTDATA_ZA_PROXY,
  MX: process.env.BRIGHTDATA_MX_PROXY,
  MY: process.env.BRIGHTDATA_MY_PROXY,
  IT: process.env.BRIGHTDATA_IT_PROXY,
  TH: process.env.BRIGHTDATA_TH_PROXY,
  NL: process.env.BRIGHTDATA_NL_PROXY,
  IL: process.env.BRIGHTDATA_IL_PROXY
};

//Make sure all proxy values exist at runtime or fail fast on startup.
Object.entries(regionZoneMap).forEach(([region, zone]) => {
    if (!zone) {
      console.warn(`⚠️ Missing proxy config for region: ${region}`);
    }
});

//Load regions
console.log("Loaded all available proxy regions:", Object.keys(regionZoneMap).filter(r => regionZoneMap[r]));

// Helper to get browser WebSocket endpoint
function getBrowserWss(regionCode) {
  const zone = regionZoneMap[regionCode?.toUpperCase()];
  const password = process.env.BRIGHTDATA_PASSWORD;

  if (!zone || !password) {
    throw new Error(`Missing proxy configuration for region: ${regionCode}`);
  }

  return `wss://${zone}:${password}@brd.superproxy.io:9222`;
}

// Random User-Agents
const userAgents = {
  desktop: [
    // Existing ones
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.61",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",

    // 🔼 New additions
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
  ],
  mobile: [
    // Existing ones
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/123.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; moto g power (2023)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",

    // 🔼 New additions
    "Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
  ]
};

// Helper: Randomly pick desktop or mobile UA and related settings
// function getRandomUserAgent() {
//   const type = Math.random() < 0.5 ? 'desktop' : 'mobile';
//   const uaList = userAgents[type];
//   const userAgent = uaList[Math.floor(Math.random() * uaList.length)];
//   return { userAgent, isMobile: type === 'mobile' };
// }

// Helper: Randomly pick desktop or mobile UA and related settings
function getRandomUserAgent(type) {
  let uaType = type;
  if (!uaType || uaType === 'random' || (uaType !== 'desktop' && uaType !== 'mobile')) {
    uaType = Math.random() < 0.5 ? 'desktop' : 'mobile';
  }
  const uaList = userAgents[uaType];
  const userAgent = uaList[Math.floor(Math.random() * uaList.length)];
  return { userAgent, isMobile: uaType === 'mobile', uaType };
}

// Main Puppeteer logic
async function resolveWithBrowserAPI(inputUrl, region = "US", uaType) {
  const browserWSEndpoint = getBrowserWss(region);
  const browser = await puppeteer.connect({ browserWSEndpoint });

  try {
    const page = await browser.newPage();
    
    // ⬇️ Block unnecessary resources to speed things up
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const blockedResources = ["image", "stylesheet", "font", "media", "other"];
      if (blockedResources.includes(req.resourceType())) {
        req.abort();
      } else {
        req.continue();
      }
    });

    // ✅ Set custom User-Agent before navigating
    const { userAgent, isMobile } = getRandomUserAgent(uaType);
    console.log(`[INFO] Using ${isMobile ? 'Mobile' : 'Desktop'} User-Agent:\n${userAgent}`);
    await page.setUserAgent(userAgent);

    // Set realistic viewport based on UA type
    if (isMobile) {
      await page.setViewport({
        width: 375 + Math.floor(Math.random() * 20) - 10,
        height: 812 + Math.floor(Math.random() * 20) - 10,
        isMobile: true,
        hasTouch: true,
        deviceScaleFactor: 2,
      });
    } else {
      await page.setViewport({
        width: 1366 + Math.floor(Math.random() * 20) - 10,
        height: 768 + Math.floor(Math.random() * 20) - 10,
        isMobile: false,
      });
    }

    page.setDefaultNavigationTimeout(20000);

    // Determine navigation timeout (use env variable or fallback to 60 seconds)
    const envTimeout = Number(process.env.NAVIGATION_TIMEOUT);
    const timeout = isNaN(envTimeout) ? 60000 : envTimeout;

    if (!isNaN(envTimeout)) {
        console.log(`[INFO] Using navigation timeout: ${timeout} ms`);
    } else {
        console.log("[INFO] Using default timeout of 60000 ms");
    }

    // Validate the input URL
    if (!inputUrl || typeof inputUrl !== 'string' || !inputUrl.startsWith('http')) {
        console.error('[ERROR] Invalid or missing input URL:', inputUrl);
        process.exit(1);
    }

    // Attempt to navigate to the URL with the specified timeout and handle errors gracefully
    try {
      await page.goto(inputUrl, { waitUntil: "domcontentloaded", timeout: timeout });
    } catch (err) {
      console.error(`[ERROR] Failed to navigate to ${inputUrl}:`, err.message);
    }

    // Optional wait
    await page.waitForSelector("body", {timeout: 120000});

    // Get resolved final URL
    const finalUrl = page.url();

    // Detect IP info from inside the browser
    const ipData = await page.evaluate(async () => {
      try {
        const res = await fetch("https://get.geojs.io/v1/ip/geo.json");
        return await res.json(); // { ip, country_name, region, city, etc. }
      } catch (e) {
        return { error: "IP lookup failed" };
      }
    });
    return { finalUrl, ipData };
  } catch(err){
    console.log(`[ERROR] ${err.message}`);
    return {error: err.message};
  } finally {
    await browser.disconnect();
  }
}

// Timing stats
const TIMING_STATS_FILE = path.join(__dirname, 'public', 'time-stats', 'time-stats.json');

async function appendTimingStat(stat) {
  let stats = [];
  try {
    const data = await fs.readFile(TIMING_STATS_FILE, 'utf-8');
    stats = JSON.parse(data);
  } catch (e) {
    // File may not exist yet
    stats = [];
  }
  stats.push(stat);
  // Keep only last 31 days
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 31);
  stats = stats.filter(s => new Date(s.date) >= cutoff);
  await fs.writeFile(TIMING_STATS_FILE, JSON.stringify(stats, null, 2));
}

app.get('/time-stats', async (req, res) => {
  try {
    let stats = [];
    try {
      const data = await fs.readFile(TIMING_STATS_FILE, 'utf-8');
      stats = JSON.parse(data);
    } catch (e) {
      stats = [];
    }
    // Optional: filter by date range
    const { start, end } = req.query;
    if (start || end) {
      stats = stats.filter(row => {
        return (!start || row.date >= start) && (!end || row.date <= end);
      });
    }
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load timing stats', details: err.message });
  }
});

// API route: /resolve?url=https://domain.com&region=ua - /resolve?url=https://domain.com&region=ua&uaType=desktop|mobile
app.get("/resolve", async (req, res) => {
  const { url: inputUrl, region = "US", uaType } = req.query;

  if (!inputUrl) {
    return res.status(400).json({ error: "Missing URL parameter" });
  }

  try {
    new URL(inputUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  console.log(`⌛ Requested new URL: ${inputUrl}`);
  // console.log(`🌐 Resolving URL for region [${region}]:`, inputUrl);
  console.log(`🌐 Resolving URL for region [${region}] with uaType [${uaType}]:`, inputUrl);

  try {
    const startTime = Date.now();
    const { finalUrl, ipData } = await resolveWithBrowserAPI(inputUrl, region, uaType);
    const endTime = Date.now();
    const timeTaken = endTime - startTime;

    if (finalUrl) {
      resolutionStats.success++;
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].success++;
    } else {
      resolutionStats.failure++;
      resolutionStats.failedUrls.push({ url: inputUrl, region, reason: "Final URL not resolved" });
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].failure++;
    }

    // Save timing stat (date, url, time)
    const today = new Date().toISOString().slice(0, 10);
    await appendTimingStat({ date: today, url: inputUrl, time: timeTaken });
    
    console.log(`URL Resolution Completed For: ${inputUrl}`);
    console.log(`→ Original URL: ${inputUrl}`);
    
    if(finalUrl){
      console.log(`→ Final URL   : ${finalUrl}`);
    } else {
      console.log(`⚠️ Final URL could not be resolved.`);
    }

    console.log(`→ URLs Resolved with [${region}] Check IP Data ⤵`);
    if (ipData?.ip) {
        console.log(`🌍 IP Info : ${ipData.ip} (${ipData.country || "Unknown Country"} - ${ipData.region || "Unknown Region"} - ${ipData.country_code || "Unknown country_code"})`);
        console.log(`🔍 Region Match: ${ipData.country_code?.toUpperCase() === region.toUpperCase() ? '✅ YES' : '❌ NO'}`);
    }

    const hasClickId = finalUrl ? finalUrl.includes("clickid=") || finalUrl.includes("clickId=") : false;

    // Log activity for user
    await logUserActivity(req, 'resolve_url', `Resolved URL: ${inputUrl} → ${finalUrl || 'FAILED'} [${region}]`);

    return res.json({
      originalUrl: inputUrl,
      finalUrl,
      region,
      requestedRegion: region,
      actualRegion: ipData?.country_code?.toUpperCase() || 'Unknown',
      regionMatch: ipData?.country_code?.toUpperCase() === region.toUpperCase(),
      method: "browser-api",
      hasClickId,
      hasClickRef: finalUrl?.includes("clickref="),
      hasUtmSource: finalUrl?.includes("utm_source="),
      hasImRef: finalUrl?.includes("im_ref="),
      hasMtkSource: finalUrl?.includes("mkt_source="),
      hasTduId: finalUrl?.includes("tduid="),
      hasPublisherId: finalUrl?.includes("publisherId="),
      ipData, // Region detection info
      uaType
    });
  } catch (err) {
    await logUserActivity(req, 'resolve_url_failed', `Failed to resolve URL: ${inputUrl} [${region}] - ${err.message}`);
    resolutionStats.failure++;
    resolutionStats.failedUrls.push({ url: inputUrl, region, reason: err.message });
    resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
    resolutionStats.perRegion[region].failure++;

    console.error(`❌ Resolution failed:`, err.stack || err.message);
    return res.status(500).json({ error: "❌ Resolution failed", details: err.message });
  }
});

//Allow users to request resolution across multiple regions at once, getting all the resolved URLs at the same time.
// Endpoint to access this - /resolve-multiple?url=https://domain.com&regions=us,ca,ae - https://domain.com&regions=us,ca,ae&uaType=desktop|mobile
app.get('/resolve-multiple', async (req, res) => {
  const { url: inputUrl, regions, uaType } = req.query;

  if (!inputUrl || !regions) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const regionList = regions.split(',');
  const promises = regionList.map(region => resolveWithBrowserAPI(inputUrl, region, uaType));
  const results = await Promise.all(promises);

  results.forEach((result, i) => {
    const region = regionList[i];
    resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };

    if (result.finalUrl) {
      resolutionStats.success++;
      resolutionStats.perRegion[region].success++;
    } else {
      resolutionStats.failure++;
        resolutionStats.failedUrls.push({
        url: inputUrl,
        region,
        reason: result.error || "Final URL not resolved"
      });
      resolutionStats.perRegion[region].failure++;
    }
  });

  // Log activity for user
  await logUserActivity(req, 'resolve_multiple', `Resolved URL: ${inputUrl} for regions: ${regions}`);

  res.json({
    originalUrl: inputUrl,
    results: results.map((result, index) => ({
      region: regionList[index],
      finalUrl: result.finalUrl,
      ipData: result.ipData,
    })),
  });
});

// Enhanced BrightData API Usage Endpoint with Bandwidth Features /zone-usage - /zone-usage?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/zone-usage', (req, res) => {
  const { from, to } = req.query;

  if (!from || !to) {
    return res.status(400).json({
      error: 'Please provide both "from" and "to" query parameters in YYYY-MM-DD format.',
    });
  }

  const options = {
    hostname: 'api.brightdata.com',
    path: `/zone/bw?zone=${ZONE}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    method: 'GET',
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      Accept: 'application/json',
    },
    rejectUnauthorized: false, // ignore SSL certificate issues
  };

  const apiReq = https.request(options, (apiRes) => {
    let data = '';

    apiRes.on('data', (chunk) => {
      data += chunk;
    });

    apiRes.on('end', () => {
      try {
        const json = JSON.parse(data);
        console.log('Raw API response:', json);

        const result = {};
        
        // Access the zone data (keeping original structure)
        const zoneData = json.c_a4a3b5b0.data?.[ZONE];
        const { reqs_browser_api, bw_browser_api, bw_sum } = zoneData || {};

        console.log('Zone data:', zoneData);

        if (reqs_browser_api && bw_browser_api) {
          // Create a list of dates between 'from' and 'to'
          const dates = getDatesBetween(from, to);

          // Match dates to request and bandwidth data
          dates.forEach((date, index) => {
            result[date] = {
              requests: reqs_browser_api[index] || 0,
              bandwidth: bw_browser_api[index] || 0 // in bytes
            };
          });
        }

        // Add summary statistics
        const summary = {
          totalBandwidth: bw_sum ? (bw_sum[0] || 0) : 0, // Total bandwidth in bytes
          totalRequests: reqs_browser_api ? reqs_browser_api.reduce((sum, val) => sum + val, 0) : 0,
          dateRange: {
            from: from,
            to: to
          }
        };

        res.json({ 
          data: result,
          summary: summary
        });
        
      } catch (e) {
        console.error('Error parsing response:', e);
        res.status(500).json({
          error: 'Failed to parse Bright Data API response.',
          details: e.message,
        });
      }
    });
  });

  apiReq.on('error', (e) => {
    console.error('Request error:', e.message);
    res.status(500).json({
      error: 'Request to Bright Data API failed.',
      details: e.message,
    });
  });

  apiReq.end();
});

// Helper function to get all dates between 'from' and 'to' (unchanged)
function getDatesBetween(startDate, endDate) {
  const dates = [];
  const currentDate = new Date(startDate);
  const end = new Date(endDate);

  while (currentDate <= end) {
    dates.push(currentDate.toISOString().split('T')[0]);
    currentDate.setDate(currentDate.getDate() + 1);
  }

  return dates;
}

// Regions check
app.get("/regions", (req, res) => {
  res.json(Object.keys(regionZoneMap));
});

app.get("/system-info", (req, res) => {
  const memoryUsage = process.memoryUsage();
  const uptime = process.uptime();
  const loadAverage = os.loadavg();
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();

  const healthCheck = {
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(uptime)} seconds`,
    memory: {
      rss: `${(memoryUsage.rss / 1024 / 1024).toFixed(2)} MB`,
      heapTotal: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
      heapUsed: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      external: `${(memoryUsage.external / 1024 / 1024).toFixed(2)} MB`,
    },
    loadAverage: {
      "1m": loadAverage[0].toFixed(2),
      "5m": loadAverage[1].toFixed(2),
      "15m": loadAverage[2].toFixed(2),
    },
    memoryStats: {
      total: `${(totalMemory / 1024 / 1024).toFixed(2)} MB`,
      free: `${(freeMemory / 1024 / 1024).toFixed(2)} MB`,
    },
    cpu: {
      cores: os.cpus().length,
      model: os.cpus()[0].model,
    },
    healthy: freeMemory / totalMemory > 0.1 && loadAverage[0] < os.cpus().length,
  };

  res.status(200).json(healthCheck);
});

// Fallback for homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Get the usage.html file from analytics folder and making an endpoint
app.get('/analytics/usage.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'analytics', 'usage.html'));
});

//serve it via a clean route
app.get("/resolutions-stats/resolutions.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'resolutions-stats', 'resolutions.html'));
});

//serve it via a clean route endpoint like /resolution-stats
app.get("/resolution-stats", (req, res) => {
  res.json({
    totalSuccess: resolutionStats.success,
    totalFailure: resolutionStats.failure,
    perRegion: resolutionStats.perRegion,
    failedUrls: resolutionStats.failedUrls
  });
});

// IP endpoint
app.get('/ip', (req, res) => {
  const rawIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket?.remoteAddress ||
    req.ip;

  // Remove IPv6 prefix if present
  const clientIp = rawIp?.replace(/^::ffff:/, '');

  console.log(`Client IP: ${clientIp}`);
  res.send({ ip : clientIp });
});

// Registration Route
app.post('/register', express.json(), async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, role && ['user','admin'].includes(role) ? role : 'user']
    );
    res.json({ message: 'User registered successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      if (req.accepts('html')) {
        return res.redirect('/auth/login.html?error=1');
      } else {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      if (req.accepts('html')) {
        return res.redirect('/auth/login.html?error=1');
      } else {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    await pool.query('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)', [user.id, 'login', 'User logged in']);
    if (req.accepts('html')) {
      return res.redirect('/dashboard.html');
    } else {
      return res.json({ message: 'Login successful.' });
    }
  } catch (err) {
    if (req.accepts('html')) {
      return res.redirect('/auth/login.html?error=1');
    } else {
      return res.status(500).json({ error: 'Login failed.' });
    }
  }
});

// Dashboard API: User summary and activity logs
app.get('/api/dashboard/summary', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const userId = req.session.user.id;
  const isAdmin = req.session.user.role === 'admin';
  const search = req.query.search ? `%${req.query.search}%` : null;
  const actionFilter = req.query.action ? `%${req.query.action}%` : null;
  const detailsFilter = req.query.details ? `%${req.query.details}%` : null;
  try {
    if (isAdmin) {
      // Admin: get all users and their stats, with optional search and filters
      let usersQuery = 'SELECT id, username, role FROM users';
      let usersParams = [];
      if (search) {
        usersQuery += ' WHERE username LIKE ?';
        usersParams.push(search);
      }
      const [users] = await pool.query(usersQuery, usersParams);
      // For each user, get stats and all activity logs (with filters)
      const userStats = await Promise.all(users.map(async user => {
        const [loginRows] = await pool.query(
          "SELECT COUNT(*) AS loginCount, MAX(timestamp) AS lastLogin FROM activity_logs WHERE user_id = ? AND action = 'login'",
          [user.id]
        );
        const [urlRows] = await pool.query(
          "SELECT COUNT(*) AS urlCount FROM activity_logs WHERE user_id = ? AND action = 'generate_url'",
          [user.id]
        );
        // Build activity log query with filters
        let activityQuery = "SELECT action, details, timestamp FROM activity_logs WHERE user_id = ?";
        let activityParams = [user.id];
        if (actionFilter) {
          activityQuery += " AND action LIKE ?";
          activityParams.push(actionFilter);
        }
        if (detailsFilter) {
          activityQuery += " AND details LIKE ?";
          activityParams.push(detailsFilter);
        }
        activityQuery += " ORDER BY timestamp DESC LIMIT 100";
        const [activityLogs] = await pool.query(activityQuery, activityParams);
        return {
          userId: user.id,
          username: user.username,
          role: user.role,
          loginCount: loginRows[0].loginCount,
          lastLogin: loginRows[0].lastLogin,
          urlCount: urlRows[0].urlCount,
          activityLogs: activityLogs.map(log => ({ ...log, username: user.username }))
        };
      }));
      res.json({ isAdmin: true, userStats });
  } else {
      // Normal user: only their own stats
      const [loginRows] = await pool.query(
        "SELECT COUNT(*) AS loginCount, MAX(timestamp) AS lastLogin FROM activity_logs WHERE user_id = ? AND action = 'login'",
        [userId]
      );
      const [urlRows] = await pool.query(
        "SELECT COUNT(*) AS urlCount FROM activity_logs WHERE user_id = ? AND action = 'generate_url'",
        [userId]
      );
      const [activityLogs] = await pool.query(
        "SELECT action, details, timestamp FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100",
        [userId]
      );
      res.json({
        isAdmin: false,
        username: req.session.user.username,
        loginCount: loginRows[0].loginCount,
        lastLogin: loginRows[0].lastLogin,
        urlCount: urlRows[0].urlCount,
        activityLogs
      });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// Dashboard API: List all users (admin only)
app.get('/api/dashboard/users', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const [users] = await pool.query('SELECT id, username, role FROM users');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin: Change user role (accept JSON)
app.post('/admin/change-role', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { userId, newRole } = req.body;
  if (!userId || !newRole) return res.status(400).json({ error: 'Missing userId or newRole' });
  try {
    await pool.query('UPDATE users SET role = ? WHERE id = ?', [newRole, userId]);
    res.json({ message: 'User role updated.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role.' });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/auth/login.html');
  });
});

//Keep Render service awake by pinging itself every 14 minutes
// setInterval(() => {
//   const url = 'https://tracetoend.onrender.com/ip'; // Replace with your actual Render URL

//   https.get(url, (res) => {
//     console.log(`[KEEP-AWAKE] Pinged self. Status code: ${res.statusCode}`);
//   }).on('error', (err) => {
//     console.error('[KEEP-AWAKE] Self-ping error:', err.message);
//   });
// }, 14 * 60 * 1000); // every 10 minutes

app.listen(PORT, () => {
  console.log(`🚀 Region-aware resolver running at http://localhost:${PORT}`);
});

// Helper to log activity for the current user
async function logUserActivity(req, action, details = '') {
  if (req.session && req.session.user) {
    await pool.query(
      'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, action, details]
    );
  }
}

// Add activity logging to /resolve (single URL resolution)
app.get("/resolve", async (req, res) => {
  const { url: inputUrl, region = "US", uaType } = req.query;
  if (!inputUrl) {
    return res.status(400).json({ error: "Missing URL parameter" });
  }
  try {
    new URL(inputUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }
  try {
    const startTime = Date.now();
    const { finalUrl, ipData } = await resolveWithBrowserAPI(inputUrl, region, uaType);
    const endTime = Date.now();
    const timeTaken = endTime - startTime;

    if (finalUrl) {
      resolutionStats.success++;
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].success++;
    } else {
      resolutionStats.failure++;
      resolutionStats.failedUrls.push({ url: inputUrl, region, reason: "Final URL not resolved" });
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].failure++;
    }

    // Save timing stat (date, url, time)
    const today = new Date().toISOString().slice(0, 10);
    await appendTimingStat({ date: today, url: inputUrl, time: timeTaken });
    
    console.log(`URL Resolution Completed For: ${inputUrl}`);
    console.log(`→ Original URL: ${inputUrl}`);
    
    if(finalUrl){
      console.log(`→ Final URL   : ${finalUrl}`);
    } else {
      console.log(`⚠️ Final URL could not be resolved.`);
    }

    console.log(`→ URLs Resolved with [${region}] Check IP Data ⤵`);
    if (ipData?.ip) {
        console.log(`🌍 IP Info : ${ipData.ip} (${ipData.country || "Unknown Country"} - ${ipData.region || "Unknown Region"} - ${ipData.country_code || "Unknown country_code"})`);
        console.log(`🔍 Region Match: ${ipData.country_code?.toUpperCase() === region.toUpperCase() ? '✅ YES' : '❌ NO'}`);
    }

    const hasClickId = finalUrl ? finalUrl.includes("clickid=") || finalUrl.includes("clickId=") : false;

    // Log activity for user
    await logUserActivity(req, 'resolve_url', `Resolved URL: ${inputUrl} → ${finalUrl || 'FAILED'} [${region}]`);

    return res.json({
      originalUrl: inputUrl,
      finalUrl,
      region,
      requestedRegion: region,
      actualRegion: ipData?.country_code?.toUpperCase() || 'Unknown',
      regionMatch: ipData?.country_code?.toUpperCase() === region.toUpperCase(),
      method: "browser-api",
      hasClickId,
      hasClickRef: finalUrl?.includes("clickref="),
      hasUtmSource: finalUrl?.includes("utm_source="),
      hasImRef: finalUrl?.includes("im_ref="),
      hasMtkSource: finalUrl?.includes("mkt_source="),
      hasTduId: finalUrl?.includes("tduid="),
      hasPublisherId: finalUrl?.includes("publisherId="),
      ipData, // Region detection info
      uaType
    });
  } catch (err) {
    await logUserActivity(req, 'resolve_url_failed', `Failed to resolve URL: ${inputUrl} [${region}] - ${err.message}`);
    resolutionStats.failure++;
    resolutionStats.failedUrls.push({ url: inputUrl, region, reason: err.message });
    resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
    resolutionStats.perRegion[region].failure++;

    console.error(`❌ Resolution failed:`, err.stack || err.message);
    return res.status(500).json({ error: "❌ Resolution failed", details: err.message });
  }
});

// Add activity logging to /resolve-multiple
app.get('/resolve-multiple', async (req, res) => {
  const { url: inputUrl, regions, uaType } = req.query;
  if (!inputUrl || !regions) {
    return res.status(400).json({ error: "Missing parameters" });
  }
  const regionList = regions.split(',');
  try {
    const results = await Promise.all(regionList.map(region => resolveWithBrowserAPI(inputUrl, region, uaType)));
    // Log activity for user
    await logUserActivity(req, 'resolve_multiple', `Resolved URL: ${inputUrl} for regions: ${regions}`);
    results.forEach((result, i) => {
      const region = regionList[i];
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };

      if (result.finalUrl) {
        resolutionStats.success++;
        resolutionStats.perRegion[region].success++;
      } else {
        resolutionStats.failure++;
          resolutionStats.failedUrls.push({
          url: inputUrl,
          region,
          reason: result.error || "Final URL not resolved"
        });
        resolutionStats.perRegion[region].failure++;
      }
    });
    res.json({
      originalUrl: inputUrl,
      results: results.map((result, index) => ({
        region: regionList[index],
        finalUrl: result.finalUrl,
        ipData: result.ipData,
      })),
    });
  } catch (err) {
    await logUserActivity(req, 'resolve_multiple_failed', `Failed to resolve URL: ${inputUrl} for regions: ${regions} - ${err.message}`);
    return res.status(500).json({ error: "❌ Resolution failed", details: err.message });
  }
});

// Add activity logging to campaign creation and CSV upload
// (Assume you POST to /campaign for single, /campaigns/upload for CSV)
app.post('/campaign', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const { url, tags, country, uaType } = req.body;
  if (!url || !country) return res.status(400).json({ error: 'URL and Country required for campaign.' });
  await logUserActivity(req, 'add_campaign', `Campaign: ${url} [${country}] Tags: ${tags} UA: ${uaType}`);
  res.json({ message: 'Campaign added (activity logged).' });
});

app.post('/campaigns/upload', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const { campaigns } = req.body; // array of {url, tags, country, uaType}
  if (!Array.isArray(campaigns)) return res.status(400).json({ error: 'Invalid campaigns data' });
  await logUserActivity(req, 'upload_csv', `Uploaded ${campaigns.length} campaigns via CSV.`);
  res.json({ message: 'CSV upload processed (activity logged).' });
});