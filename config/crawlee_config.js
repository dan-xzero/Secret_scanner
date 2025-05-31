// ===================================
// CRAWLEE CONFIGURATION
// ===================================

const { LogLevel } = require('crawlee');
const path = require('path');

module.exports = {
  // General Crawler Settings
  crawler: {
    // Maximum number of pages to crawl
    maxRequestsPerCrawl: parseInt(process.env.CRAWLER_MAX_REQUESTS_PER_CRAWL) || 1000,
    
    // Maximum crawl depth
    maxCrawlingDepth: parseInt(process.env.SCAN_DEPTH) || 3,
    
    // Request timeout in milliseconds
    navigationTimeout: parseInt(process.env.CRAWLER_TIMEOUT) || 30000,
    
    // Maximum concurrent requests
    maxConcurrency: parseInt(process.env.CONCURRENT_REQUESTS) || 10,
    
    // Minimum concurrent requests
    minConcurrency: 2,
    
    // Request handler timeout
    requestHandlerTimeoutSecs: 60,
    
    // Max requests per minute (rate limiting)
    maxRequestsPerMinute: 300,
    
    // Retry configuration
    maxRequestRetries: parseInt(process.env.MAX_RETRIES) || 3,
    
    // Request queue
    requestQueueOptions: {
      maxQueueSize: 10000,
      persistStorage: true,
    },
    
    // Session pool options
    sessionPoolOptions: {
      maxPoolSize: 100,
      persistStateKey: 'session-pool-state',
    },
    
    // Keep URL fragments
    keepUrlFragments: false,
    
    // User agent
    userAgent: process.env.USER_AGENT || 'Mozilla/5.0 (Compatible; SecretsScanner/1.0)',
  },

  // Playwright-specific Settings
  playwright: {
    // Browser to use
    browserType: process.env.CRAWLER_BROWSER || 'chromium', // chromium, firefox, webkit
    
    // Launch options
    launchOptions: {
      headless: process.env.CRAWLER_HEADLESS !== 'false',
      
      // Browser args
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-blink-features=AutomationControlled',
      ],
      
      // Slow down browser actions (useful for debugging)
      slowMo: process.env.APP_DEBUG === 'true' ? 100 : 0,
      
      // Browser executable path (optional)
      // executablePath: '/usr/bin/chromium-browser',
      
      // Proxy settings
      proxy: process.env.PROXY_URL ? {
        server: process.env.PROXY_URL,
        username: process.env.PROXY_USERNAME,
        password: process.env.PROXY_PASSWORD,
      } : undefined,
    },
    
    // Context options
    contextOptions: {
      viewport: {
        width: parseInt(process.env.CRAWLER_VIEWPORT_WIDTH) || 1920,
        height: parseInt(process.env.CRAWLER_VIEWPORT_HEIGHT) || 1080,
      },
      
      // User agent override
      userAgent: process.env.USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      
      // Ignore HTTPS errors
      ignoreHTTPSErrors: process.env.VERIFY_SSL_CERTIFICATES === 'false',
      
      // Locale
      locale: 'en-US',
      
      // Timezone
      timezoneId: 'America/New_York',
      
      // Permissions
      permissions: ['geolocation', 'notifications'],
      
      // Device scale factor
      deviceScaleFactor: 1,
      
      // Mobile emulation
      isMobile: false,
      
      // Offline mode
      offline: false,
      
      // JavaScript enabled
      javaScriptEnabled: process.env.ENABLE_JAVASCRIPT !== 'false',
      
      // Accept downloads
      acceptDownloads: false,
      
      // Record video
      recordVideo: process.env.ENABLE_SCREENSHOT_CAPTURE === 'true' ? {
        dir: path.join(process.env.DATA_STORAGE_PATH || './data', 'videos'),
        size: { width: 1280, height: 720 },
      } : undefined,
    },
    
    // Page goto options
    gotoOptions: {
      waitUntil: process.env.CRAWLER_WAIT_UNTIL || 'networkidle',
      timeout: parseInt(process.env.CRAWLER_TIMEOUT) || 30000,
    },
    
    // Pre-navigation hooks
    preNavigationHooks: [
      async ({ page, request }) => {
        // Block resources to speed up crawling
        const blockedResources = (process.env.CRAWLER_BLOCK_RESOURCES || 'image,media,font').split(',');
        
        await page.route('**/*', (route) => {
          const resourceType = route.request().resourceType();
          if (blockedResources.includes(resourceType)) {
            route.abort();
          } else {
            route.continue();
          }
        });
        
        // Set extra headers if configured
        if (process.env.CUSTOM_HEADERS) {
          try {
            const headers = JSON.parse(process.env.CUSTOM_HEADERS);
            await page.setExtraHTTPHeaders(headers);
          } catch (error) {
            console.error('Failed to parse custom headers:', error);
          }
        }
        
        // Set cookies if configured
        if (process.env.CUSTOM_COOKIES) {
          try {
            const cookies = JSON.parse(process.env.CUSTOM_COOKIES);
            await page.context().addCookies(cookies);
          } catch (error) {
            console.error('Failed to parse custom cookies:', error);
          }
        }
        
        // Console message handling
        page.on('console', (msg) => {
          if (process.env.APP_DEBUG === 'true') {
            console.log(`Browser console [${msg.type()}]:`, msg.text());
          }
        });
        
        // Page error handling
        page.on('pageerror', (error) => {
          console.error('Page error:', error);
        });
        
        // Request failure handling
        page.on('requestfailed', (request) => {
          console.error('Request failed:', request.url(), request.failure().errorText);
        });
      },
    ],
    
    // Post-navigation hooks
    postNavigationHooks: [
      async ({ page, request }) => {
        // Wait for dynamic content to load
        if (process.env.ENABLE_JAVASCRIPT === 'true') {
          try {
            await page.waitForTimeout(parseInt(process.env.JAVASCRIPT_TIMEOUT) || 5000);
          } catch (error) {
            console.warn('JavaScript timeout reached:', error.message);
          }
        }
        
        // Take screenshot if enabled
        if (process.env.ENABLE_SCREENSHOT_CAPTURE === 'true') {
          const screenshotPath = path.join(
            process.env.SCREENSHOT_PATH || './data/screenshots',
            `${Date.now()}_${request.url.replace(/[^a-z0-9]/gi, '_')}.png`
          );
          
          try {
            await page.screenshot({
              path: screenshotPath,
              fullPage: true,
            });
          } catch (error) {
            console.error('Failed to take screenshot:', error);
          }
        }
        
        // Export HAR if enabled
        if (process.env.ENABLE_HAR_EXPORT === 'true') {
          // Note: HAR export requires additional implementation
          console.log('HAR export requested for:', request.url);
        }
      },
    ],
  },

  // Storage Configuration
  storage: {
    // Dataset configuration
    dataset: {
      outputPath: path.join(process.env.DATA_STORAGE_PATH || './data', 'content'),
      format: 'json',
      clean: false,
    },
    
    // Request queue
    requestQueue: {
      persistStorage: true,
      cachePath: path.join(process.env.DATA_STORAGE_PATH || './data', 'cache/request-queue'),
    },
    
    // Key-value store
    keyValueStore: {
      persistStorage: true,
      cachePath: path.join(process.env.DATA_STORAGE_PATH || './data', 'cache/key-value-store'),
    },
  },

  // URL Processing
  urlProcessing: {
    // URL patterns to include (regex)
    includePatterns: [ ],
    
    // URL patterns to exclude (regex)
    excludePatterns: [
      '.*\\.(jpg|jpeg|png|gif|svg|ico|webp)$',
      '.*\\.(css|scss|sass|less)$',
      '.*\\.(woff|woff2|ttf|eot|otf)$',
      '.*\\.(mp4|mp3|avi|mov|wmv|flv|webm)$',
      '.*\\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$',
      '.*\\.(zip|rar|tar|gz|7z)$',
      '.*/wp-admin/.*',
      '.*/admin/.*',
      '.*\\.min\\.js$',
      '.*\\.min\\.css$',
      '.*\\/node_modules\\/.*',
      '.*\\/vendor\\/.*',
      '.*\\/\\.git\\/.*',
    ].concat(
      (process.env.EXCLUDE_EXTENSIONS || '').split(',').filter(Boolean).map(ext => `.*\\.${ext}$`)
    ),
    
    // Focus paths (prioritize these)
    focusPaths: (process.env.FOCUS_PATHS || '/api,/config,/js,/scripts').split(',').filter(Boolean),
    
    // Ignore domains
    ignoreDomains: (process.env.IGNORE_DOMAINS || 'google-analytics.com,doubleclick.net').split(',').filter(Boolean),
    
    // Ignore paths
    ignorePaths: (process.env.IGNORE_PATHS || '/wp-admin,/admin,/.git').split(',').filter(Boolean),
  },

  // Content Extraction
  contentExtraction: {
    // Save HTML content
    saveHtml: true,
    
    // Save JavaScript content
    saveJavaScript: true,
    
    // Save inline scripts
    saveInlineScripts: true,
    
    // Save JSON responses
    saveJson: true,
    
    // Maximum file size to save (bytes)
    maxFileSize: parseInt(process.env.SCAN_FILE_SIZE_LIMIT) || 10 * 1024 * 1024, // 10MB
    
    // Beautify JavaScript
    beautifyJavaScript: true,
    
    // Extract additional metadata
    extractMetadata: true,
  },

  // Error Handling
  errorHandling: {
    // Continue on errors
    continueOnError: true,
    
    // Log errors
    logErrors: true,
    
    // Error log file
    errorLogPath: path.join(process.env.LOG_FILE_PATH || './logs', 'crawler_errors.log'),
    
    // Retry failed requests
    retryFailedRequests: true,
    
    // Skip timeouts
    skipOnTimeout: true,
  },

  // Logging Configuration
  logging: {
    // Log level
    level: process.env.LOG_LEVEL || LogLevel.INFO,
    
    // Log to file
    logToFile: true,
    
    // Log file path
    logFilePath: path.join(process.env.LOG_FILE_PATH || './logs', 'crawler.log'),
    
    // Pretty print logs
    prettyPrint: process.env.APP_ENV !== 'production',
    
    // Include timestamp
    includeTimestamp: true,
    
    // Log request details
    logRequests: process.env.VERBOSE_LOGGING === 'true',
    
    // Log response details
    logResponses: process.env.VERBOSE_LOGGING === 'true',
  },

  // Performance Optimization
  performance: {
    // Memory threshold (MB)
    memoryThreshold: parseInt(process.env.MEMORY_LIMIT_MB) || 2048,
    
    // CPU threshold (percentage)
    cpuThreshold: parseInt(process.env.CPU_LIMIT_PERCENT) || 80,
    
    // Enable caching
    enableCache: process.env.ENABLE_CACHING !== 'false',
    
    // Cache TTL (seconds)
    cacheTTL: parseInt(process.env.CACHE_TTL) || 3600,
    
    // Autoscale concurrency
    autoscaleConcurrency: true,
    
    // Autoscale interval (seconds)
    autoscaleInterval: 10,
  },

  // Advanced Features
  advanced: {
    // Enable fingerprinting protection
    fingerprintingProtection: true,
    
    // Enable stealth mode
    stealthMode: true,
    
    // Enable request interception
    requestInterception: true,
    
    // Enable response interception
    responseInterception: true,
    
    // Save network activity
    saveNetworkActivity: process.env.SAVE_INTERMEDIATE_FILES === 'true',
    
    // Enable JavaScript coverage
    collectCoverage: process.env.APP_DEBUG === 'true',
  },

  // Custom Functions
  customFunctions: {
    // URL filter function
    urlFilter: (url) => {
      // Custom URL filtering logic
      const urlObj = new URL(url);
      
      // Check if URL should be crawled
      if (process.env.ENABLE_HTTPS_ONLY === 'true' && urlObj.protocol !== 'https:') {
        return false;
      }
      
      return true;
    },
    
    // Request transform function
    requestTransform: (request) => {
      // Custom request transformation
      return request;
    },
    
    // Response handler
    responseHandler: async (response, page) => {
      // Custom response handling
      return response;
    },
  },
};