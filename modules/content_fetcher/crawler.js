/**
 * Enhanced Crawlee-based Web Crawler for Secret Scanner
 * WITH PRECISE URL MAPPING AND RESOURCE RELATIONSHIP TRACKING
 * 
 * Modified to track exact parent-child relationships between pages and JavaScript chunks
 * FIXED: Parent page URL detection for dynamically loaded JS chunks
 */

const { PlaywrightCrawler, Dataset, KeyValueStore, log, LogLevel } = require('crawlee');
const { promises: fs } = require('fs');
const path = require('path');
const crypto = require('crypto');
const beautify = require('js-beautify');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const winston = require('winston');
require('winston-daily-rotate-file');

// Load configuration
const crawleeConfig = require('../../config/crawlee_config');

// Parse command line arguments
const argv = yargs(hideBin(process.argv))
  .option('input', {
    alias: 'i',
    description: 'Input file containing URLs',
    type: 'string',
    demandOption: true
  })
  .option('output', {
    alias: 'o',
    description: 'Output directory for fetched content',
    type: 'string',
    demandOption: true
  })
  .option('scan-id', {
    alias: 's',
    description: 'Scan ID for precise resource tracking',
    type: 'string',
    default: `scan_${Date.now()}`
  })
  .option('url-mapping', {
    alias: 'u',
    description: 'URL to filename mapping file',
    type: 'string'
  })
  .option('config', {
    alias: 'c',
    description: 'Configuration file path',
    type: 'string'
  })
  .option('max-requests', {
    alias: 'm',
    description: 'Maximum number of requests',
    type: 'number',
    default: 1000
  })
  .option('concurrency', {
    description: 'Number of concurrent requests',
    type: 'number',
    default: 5
  })
  .option('timeout', {
    description: 'Request timeout in seconds',
    type: 'number',
    default: 60
  })
  .option('headless', {
    description: 'Run browser in headless mode',
    type: 'boolean',
    default: true
  })
  .option('verbose', {
    alias: 'v',
    description: 'Enable verbose logging',
    type: 'boolean',
    default: false
  })
  .option('batch-size', {
    description: 'Process URLs in batches',
    type: 'number',
    default: 50
  })
  .option('enable-precise-mapping', {
    description: 'Enable precise URL mapping (experimental)',
    type: 'boolean',
    default: true
  })
  .help()
  .alias('help', 'h')
  .argv;

// Configure logging
const logger = winston.createLogger({
  level: argv.verbose ? 'debug' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.DailyRotateFile({
      filename: path.join(process.env.LOG_FILE_PATH || './logs', 'crawler-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '100m',
      maxFiles: '30d'
    })
  ]
});

// Set Crawlee log level
log.setLevel(argv.verbose ? LogLevel.DEBUG : LogLevel.INFO);

// Validate timeout
if (argv.timeout > 300) {
  logger.warn(`Timeout value ${argv.timeout} seconds seems too large, using 60 seconds instead`);
  argv.timeout = 60;
}

// Global statistics
const stats = {
  urlsProcessed: 0,
  urlsSuccessful: 0,
  urlsFailed: 0,
  htmlSaved: 0,
  jsSaved: 0,
  jsonSaved: 0,
  inlineScriptsSaved: 0,
  errors: 0,
  startTime: Date.now(),
  failedUrls: [],
  errorDetails: {},
  resourceRelationships: 0,
  preciseMappingsCreated: 0
};

// Intercepted JavaScript files with enhanced parent tracking
const interceptedJsFiles = new Map();

// Global page context tracking for precise parent URL detection
const pageContextTracker = new Map();

// URL-based filename mapping from main scanner
let providedUrlMapping = {};

// URL mappings for tracking
const urlMappings = {
  fileToUrl: {},
  urlToFile: {},
  metadata: {}
};

// Global resource relationships storage
const allResourceRelationships = [];

// Blocked domains for resource optimization
const BLOCKED_DOMAINS = [
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'facebook.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
  'amplitude.com', 'segment.com', 'mixpanel.com', 'hotjar.com',
  'cloudflare.com/cdn-cgi', 'newrelic.com', 'nr-data.net',
  'optimizely.com', 'quantserve.com', 'scorecardresearch.com',
  'adsystem.com', 'amazon-adsystem.com', 'googlesyndication.com'
];

// Blocked resource types
const BLOCKED_RESOURCE_TYPES = [
  'image', 'media', 'font', 'stylesheet', 'ping', 'websocket', 'manifest',
  'other'
];

/**
 * Enhanced Resource Tracker for Precise URL Mapping
 */
class ResourceTracker {
  constructor(page, pageUrl, scanId) {
    this.page = page;
    this.pageUrl = pageUrl;
    this.scanId = scanId;
    this.resources = [];
    this.loadStartTime = Date.now();
    this.dynamicLoads = [];
    this.setupComplete = false;
    
    // Track this page context globally
    pageContextTracker.set(page, pageUrl);
  }

  async setupTracking() {
    try {
      // Enhanced network monitoring
      this.page.on('response', async (response) => {
        await this.trackResponse(response);
      });
      
      // Inject enhanced dynamic loading detection with better parent tracking
      await this.page.addInitScript(() => {
        // Store original page URL for reference
        window.__originalPageUrl = window.location.href;
        
        // Enhanced dynamic import() tracking
        if (window.import) {
          const originalImport = window.import;
          window.import = function(specifier) {
            window.__dynamicImports = window.__dynamicImports || [];
            window.__dynamicImports.push({
              specifier: specifier,
              timestamp: Date.now(),
              parentUrl: window.__originalPageUrl || window.location.href,
              loadMethod: 'dynamic-import'
            });
            return originalImport.call(this, specifier);
          };
        }

        // Enhanced dynamic script creation tracking
        const originalCreateElement = document.createElement;
        document.createElement = function(tagName) {
          const element = originalCreateElement.call(this, tagName);
          
          if (tagName.toLowerCase() === 'script') {
            element.addEventListener('load', () => {
              window.__dynamicScripts = window.__dynamicScripts || [];
              window.__dynamicScripts.push({
                src: element.src,
                timestamp: Date.now(),
                parentUrl: window.__originalPageUrl || window.location.href,
                loadMethod: 'dynamic-script'
              });
            });
          }
          
          return element;
        };

        // Enhanced fetch() tracking for JS files
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
          const url = typeof input === 'string' ? input : input.url;
          if (url && url.endsWith('.js')) {
            window.__fetchedScripts = window.__fetchedScripts || [];
            window.__fetchedScripts.push({
              url: url,
              timestamp: Date.now(),
              parentUrl: window.__originalPageUrl || window.location.href,
              method: 'fetch'
            });
          }
          return originalFetch.call(this, input, init);
        };

        // Track webpack chunk loading patterns
        const originalWebpackLoad = window.webpackJsonp || window.__webpack_require__;
        if (originalWebpackLoad) {
          window.__webpackChunksLoaded = window.__webpackChunksLoaded || [];
          // This will be populated by webpack internals
        }

        // Track Next.js specific patterns
        if (window.next || window._N_E) {
          window.__nextJsChunks = window.__nextJsChunks || [];
          // Monitor Next.js chunk loading
        }
      });
      
      this.setupComplete = true;
      logger.debug(`ResourceTracker setup complete for ${this.pageUrl}`);
    } catch (error) {
      logger.error(`Failed to setup ResourceTracker for ${this.pageUrl}: ${error.message}`);
    }
  }

  async trackResponse(response) {
    try {
      const url = response.url();
      const request = response.request();
      const resourceType = request.resourceType();
      
      if (resourceType === 'script' || url.endsWith('.js')) {
        const loadTime = Date.now() - this.loadStartTime;
        const headers = response.headers();
        
        const resourceInfo = {
          url: url,
          filename: this.extractFilename(url),
          parentUrl: this.pageUrl,
          loadMethod: this.determineLoadMethod(request, url),
          loadTime: loadTime,
          referrer: request.headers()['referer'] || this.pageUrl,
          responseSize: headers['content-length'] || 'unknown',
          scanId: this.scanId,
          resourceType: resourceType,
          timestamp: new Date().toISOString(),
          statusCode: response.status(),
          contentType: headers['content-type'] || 'unknown',
          initiator: this.getInitiatorInfo(request),
          isThirdParty: this.isThirdPartyResource(url, this.pageUrl),
          isWebpackChunk: this.isWebpackChunk(url),
          isNextJsChunk: this.isNextJsChunk(url)
        };
        
        this.resources.push(resourceInfo);
        
        // Store in global collection
        allResourceRelationships.push(resourceInfo);
        stats.resourceRelationships++;
        
        logger.debug(`Tracked resource: ${url} loaded by ${this.pageUrl} (${loadTime}ms, ${resourceInfo.loadMethod})`);
      }
    } catch (error) {
      logger.debug(`Error tracking response for ${response.url()}: ${error.message}`);
    }
  }

  extractFilename(url) {
    return getFilenameForUrl(url, '.js');
  }

  determineLoadMethod(request, url) {
    const frame = request.frame();
    const initiator = request.headers()['sec-fetch-dest'];
    
    // Enhanced detection for webpack/Next.js patterns
    if (this.isWebpackChunk(url) || this.isNextJsChunk(url)) {
      return 'dynamic-chunk';
    }
    
    if (initiator === 'script') {
      return 'static';
    } else if (initiator === 'empty') {
      return 'dynamic';
    }
    
    // Check if it's a fetch or XHR request
    const fetchMode = request.headers()['sec-fetch-mode'];
    if (fetchMode === 'cors') {
      return 'fetch';
    }
    
    // Fallback detection
    return frame ? 'static' : 'dynamic';
  }

  isWebpackChunk(url) {
    return url.includes('/chunks/') || 
           url.includes('chunk.') || 
           /\/\d+-[a-f0-9]+\.js$/.test(url) ||
           url.includes('webpack');
  }

  isNextJsChunk(url) {
    return url.includes('/_next/static/chunks/') ||
           url.includes('/_next/static/js/') ||
           url.includes('.next/');
  }

  getInitiatorInfo(request) {
    const headers = request.headers();
    return {
      dest: headers['sec-fetch-dest'],
      mode: headers['sec-fetch-mode'],
      site: headers['sec-fetch-site']
    };
  }

  isThirdPartyResource(resourceUrl, pageUrl) {
    try {
      const resourceDomain = new URL(resourceUrl).hostname;
      const pageDomain = new URL(pageUrl).hostname;
      return resourceDomain !== pageDomain;
    } catch (error) {
      return false;
    }
  }

  async getDynamicLoads() {
    try {
      return await this.page.evaluate(() => {
        return {
          dynamicImports: window.__dynamicImports || [],
          dynamicScripts: window.__dynamicScripts || [],
          fetchedScripts: window.__fetchedScripts || [],
          webpackChunks: window.__webpackChunksLoaded || [],
          nextJsChunks: window.__nextJsChunks || []
        };
      });
    } catch (error) {
      logger.debug(`Failed to get dynamic loads: ${error.message}`);
      return {
        dynamicImports: [],
        dynamicScripts: [],
        fetchedScripts: [],
        webpackChunks: [],
        nextJsChunks: []
      };
    }
  }

  getResources() {
    return this.resources;
  }

  getResourceCount() {
    return this.resources.length;
  }
}

/**
 * Get the current page URL from context tracking
 */
function getCurrentPageUrl(page) {
  const contextUrl = pageContextTracker.get(page);
  if (contextUrl) {
    return contextUrl;
  }
  
  // Fallback: try to get from page URL
  try {
    return page.url();
  } catch (error) {
    logger.debug(`Failed to get current page URL: ${error.message}`);
    return 'unknown';
  }
}

/**
 * Load URL to filename mapping if provided
 */
async function loadUrlMapping() {
  if (argv.urlMapping) {
    try {
      const mappingContent = await fs.readFile(argv.urlMapping, 'utf-8');
      providedUrlMapping = JSON.parse(mappingContent);
      logger.info(`Loaded URL mapping for ${Object.keys(providedUrlMapping).length} URLs`);
    } catch (error) {
      logger.warn(`Failed to load URL mapping: ${error.message}`);
    }
  }
}

/**
 * Get filename for URL - uses provided mapping or generates one
 */
function getFilenameForUrl(url, extension = '') {
  // Check if we have a provided filename
  if (providedUrlMapping[url]) {
    const providedFilename = providedUrlMapping[url];
    
    // If the provided filename already has the correct extension, use it as-is
    if (providedFilename.endsWith(extension)) {
      return providedFilename;
    }
    
    // If extensions don't match, append the correct one
    if (extension && !providedFilename.endsWith(extension)) {
      // Remove any existing extension
      const base = providedFilename.replace(/\.[^.]+$/, '');
      return base + extension;
    }
    
    return providedFilename;
  }
  
  // Fallback to hash-based filename
  return getSafeFilename(url, extension);
}

/**
 * Generate a safe filename from a URL (fallback)
 */
function getSafeFilename(url, extension = '') {
  const hash = crypto.createHash('md5').update(url).digest('hex');
  const urlObj = new URL(url);
  const pathParts = urlObj.pathname.split('/').filter(p => p);
  
  let filename = hash;
  if (pathParts.length > 0) {
    const lastPart = pathParts[pathParts.length - 1];
    if (lastPart && !lastPart.includes('.')) {
      filename = `${lastPart}_${hash.substring(0, 8)}`;
    } else if (lastPart) {
      filename = `${path.basename(lastPart, path.extname(lastPart))}_${hash.substring(0, 8)}`;
    }
  }
  
  // Sanitize filename
  filename = filename.replace(/[^a-zA-Z0-9_-]/g, '_');
  
  return filename + extension;
}

/**
 * Add URL mapping with enhanced metadata
 */
function addUrlMapping(localPath, originalUrl, contentType, resourceInfo = null) {
  // Make path relative to output directory
  const relativePath = path.relative(argv.output, localPath).replace(/\\/g, '/');
  
  // Store bidirectional mapping
  const mappingData = {
    url: originalUrl,
    contentType: contentType,
    timestamp: new Date().toISOString()
  };

  // Add resource relationship data if available
  if (resourceInfo) {
    mappingData.parentUrl = resourceInfo.parentUrl;
    mappingData.loadMethod = resourceInfo.loadMethod;
    mappingData.loadTime = resourceInfo.loadTime;
    mappingData.isThirdParty = resourceInfo.isThirdParty;
    mappingData.preciseMappingEnabled = true;
    stats.preciseMappingsCreated++;
  }

  urlMappings.fileToUrl[relativePath] = mappingData;
  urlMappings.urlToFile[originalUrl] = relativePath;
  
  // Extract domain for metadata
  const urlObj = new URL(originalUrl);
  const domain = urlObj.hostname;
  
  if (!urlMappings.metadata[domain]) {
    urlMappings.metadata[domain] = {
      urls: [],
      files: [],
      resourceRelationships: []
    };
  }
  
  urlMappings.metadata[domain].urls.push(originalUrl);
  urlMappings.metadata[domain].files.push(relativePath);
  
  if (resourceInfo) {
    urlMappings.metadata[domain].resourceRelationships.push(resourceInfo);
  }
  
  logger.debug(`Mapped: ${relativePath} -> ${originalUrl}${resourceInfo ? ' (with precise mapping)' : ''}`);
}

/**
 * Save URL mappings with enhanced resource relationship data
 */
async function saveUrlMappings(outputDir) {
  const mappingPath = path.join(outputDir, 'url_mappings.json');
  const reverseMappingPath = path.join(outputDir, 'file_to_url_mappings.json');
  const resourceMappingsPath = path.join(outputDir, 'resource_relationships.json');
  
  try {
    // Save complete mappings
    await fs.writeFile(
      mappingPath, 
      JSON.stringify(urlMappings, null, 2), 
      'utf-8'
    );
    
    // Save simplified file-to-URL mapping for easy lookup
    const simplifiedMapping = {};
    for (const [file, data] of Object.entries(urlMappings.fileToUrl)) {
      simplifiedMapping[file] = data.url;
    }
    
    await fs.writeFile(
      reverseMappingPath,
      JSON.stringify(simplifiedMapping, null, 2),
      'utf-8'
    );

    // Save resource relationships
    const resourceRelationshipData = {
      relationships: allResourceRelationships,
      scanId: argv.scanId,
      timestamp: new Date().toISOString(),
      totalRelationships: allResourceRelationships.length,
      domains: [...new Set(allResourceRelationships.map(r => new URL(r.parentUrl).hostname))],
      stats: {
        staticLoads: allResourceRelationships.filter(r => r.loadMethod === 'static').length,
        dynamicLoads: allResourceRelationships.filter(r => r.loadMethod === 'dynamic').length,
        dynamicChunks: allResourceRelationships.filter(r => r.loadMethod === 'dynamic-chunk').length,
        thirdPartyResources: allResourceRelationships.filter(r => r.isThirdParty).length,
        webpackChunks: allResourceRelationships.filter(r => r.isWebpackChunk).length,
        nextJsChunks: allResourceRelationships.filter(r => r.isNextJsChunk).length
      }
    };

    await fs.writeFile(
      resourceMappingsPath,
      JSON.stringify(resourceRelationshipData, null, 2),
      'utf-8'
    );
    
    logger.info(`Saved URL mappings to ${mappingPath}`);
    logger.info(`Saved resource relationships: ${allResourceRelationships.length} relationships tracked`);
    
  } catch (error) {
    logger.error(`Failed to save URL mappings: ${error.message}`);
  }
}

/**
 * Save content to file with error handling
 */
async function saveContent(content, filePath) {
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
    logger.debug(`Saved content to: ${filePath}`);
    return true;
  } catch (error) {
    logger.error(`Failed to save content to ${filePath}: ${error.message}`);
    return false;
  }
}

/**
 * Extract inline scripts from HTML
 */
function extractInlineScripts(html) {
  const scripts = [];
  const scriptRegex = /<script(?:\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
  let match;
  
  while ((match = scriptRegex.exec(html)) !== null) {
    const scriptContent = match[1].trim();
    if (scriptContent && 
        !scriptContent.startsWith('//') && 
        !scriptContent.includes('src=') &&
        scriptContent.length > 10) {
      scripts.push({
        content: scriptContent,
        position: match.index,
        length: scriptContent.length
      });
    }
  }
  
  return scripts;
}

/**
 * Extract JavaScript URLs from HTML
 */
function extractJavaScriptUrls(html, baseUrl) {
  const jsUrls = new Set();
  const patterns = [
    /<script[^>]+src=["']([^"']+)["'][^>]*>/gi,
    /import\s+.*from\s+["']([^"']+\.js)["']/gi,
    /require\(["']([^"']+\.js)["']\)/gi
  ];
  
  patterns.forEach(regex => {
    let match;
    while ((match = regex.exec(html)) !== null) {
      try {
        const jsUrl = new URL(match[1], baseUrl).href;
        jsUrls.add(jsUrl);
      } catch (error) {
        logger.debug(`Failed to parse JS URL: ${match[1]}`);
      }
    }
  });
  
  return Array.from(jsUrls);
}

/**
 * Check if URL should be processed based on configuration
 */
function shouldProcessUrl(url) {
  if (url.startsWith('data:')) return false;
  if (url.startsWith('blob:')) return false;
  
  const { includePatterns, excludePatterns } = crawleeConfig.urlProcessing || {};
  
  if (includePatterns && includePatterns.length > 0) {
    const included = includePatterns.some(pattern => new RegExp(pattern).test(url));
    if (!included) return false;
  }
  
  if (excludePatterns && excludePatterns.length > 0) {
    const excluded = excludePatterns.some(pattern => new RegExp(pattern).test(url));
    if (excluded) return false;
  }
  
  return true;
}

/**
 * Process URLs in batches
 */
async function processUrlBatch(urls, crawler) {
  const batchSize = argv.batchSize;
  const batches = [];
  
  for (let i = 0; i < urls.length; i += batchSize) {
    batches.push(urls.slice(i, i + batchSize));
  }
  
  logger.info(`Processing ${urls.length} URLs in ${batches.length} batches`);
  
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    logger.info(`Processing batch ${i + 1}/${batches.length} (${batch.length} URLs)`);
    
    await crawler.addRequests(batch);
    
    if (i < batches.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
}

/**
 * Main crawler function
 */
async function runCrawler() {
  try {
    // Load URL mapping if provided
    await loadUrlMapping();
    
    // Read URLs from input file
    logger.info(`Reading URLs from: ${argv.input}`);
    const urlsContent = await fs.readFile(argv.input, 'utf-8');
    const urls = urlsContent
      .split('\n')
      .map(url => url.trim())
      .filter(url => url && url.startsWith('http'))
      .filter(url => shouldProcessUrl(url));
    
    logger.info(`Found ${urls.length} URLs to process`);
    logger.info(`Precise URL mapping: ${argv.enablePreciseMapping ? 'ENABLED' : 'DISABLED'}`);
    logger.info(`Scan ID: ${argv.scanId}`);
    
    if (urls.length === 0) {
      logger.warn('No valid URLs found in input file');
      return;
    }
    
    // Create output directories
    const outputDir = argv.output;
    const dirs = {
      html: path.join(outputDir, 'html'),
      js: path.join(outputDir, 'js'),
      json: path.join(outputDir, 'json'),
      inlineScripts: path.join(outputDir, 'inline-scripts'),
      metadata: path.join(outputDir, 'metadata'),
      errors: path.join(outputDir, 'errors'),
      resourceMaps: path.join(outputDir, 'resource-maps')
    };
    
    await Promise.all(Object.values(dirs).map(dir => fs.mkdir(dir, { recursive: true })));
    
    // Configure crawler
    const crawler = new PlaywrightCrawler({
      maxRequestsPerCrawl: argv.maxRequests,
      maxConcurrency: argv.concurrency,
      requestHandlerTimeoutSecs: argv.timeout,
      maxRequestRetries: 3,
      retryOnBlocked: true,
      
      launchContext: {
        launchOptions: {
          headless: argv.headless,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process'
          ]
        }
      },
      
      browserPoolOptions: {
        useFingerprints: true,
        maxOpenPagesPerBrowser: 3,
        retireBrowserAfterPageCount: 20
      },
      
      preNavigationHooks: [
        async ({ page, request }) => {
          const timeoutMs = argv.timeout * 1000;
          page.setDefaultNavigationTimeout(timeoutMs);
          page.setDefaultTimeout(timeoutMs);
          
          // Enhanced request interception with fixed parent page tracking
          await page.route('**/*', async (route) => {
            const interceptedRequest = route.request();
            const url = interceptedRequest.url();
            const resourceType = interceptedRequest.resourceType();
            
            const isBlockedDomain = BLOCKED_DOMAINS.some(domain => url.includes(domain));
            const isBlockedType = BLOCKED_RESOURCE_TYPES.includes(resourceType);
            
            if (isBlockedDomain || isBlockedType) {
              await route.abort();
              return;
            }
            
            // Special handling for JavaScript files with FIXED parent page detection
            if (resourceType === 'script' || url.endsWith('.js')) {
              try {
                const response = await route.fetch();
                if (response.ok()) {
                  const content = await response.text();
                  if (content && content.length < 10 * 1024 * 1024) {
                    
                    // FIXED: Get the correct parent page URL
                    const parentPageUrl = getCurrentPageUrl(page);
                    
                    interceptedJsFiles.set(url, {
                      content,
                      fromPage: parentPageUrl,  // ✅ FIXED - now gets actual parent page URL
                      headers: response.headers(),
                      timestamp: new Date().toISOString(),
                      scanId: argv.scanId,
                      interceptedDuringCrawl: true
                    });
                    
                    logger.debug(`Intercepted JS: ${url} from page: ${parentPageUrl}`);
                  }
                }
                await route.fulfill({ response });
              } catch (error) {
                logger.debug(`Failed to intercept JS: ${url} - ${error.message}`);
                await route.continue();
              }
            } else {
              await route.continue();
            }
          });
          
          // Add stealth measures
          await page.addInitScript(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
          });
          
          // Set custom headers
          const headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br'
          };
          
          if (process.env.CUSTOM_HEADERS) {
            try {
              Object.assign(headers, JSON.parse(process.env.CUSTOM_HEADERS));
            } catch (error) {
              logger.error(`Failed to parse custom headers: ${error.message}`);
            }
          }
          
          await page.setExtraHTTPHeaders(headers);
        }
      ],
      
      requestHandler: async ({ request, page, response }) => {
        const url = request.url;
        const startTime = Date.now();
        let resourceTracker = null;
        
        try {
          logger.info(`Processing: ${url} (attempt ${request.retryCount + 1})`);
          stats.urlsProcessed++;
          
          // Initialize ResourceTracker for precise URL mapping
          if (argv.enablePreciseMapping) {
            resourceTracker = new ResourceTracker(page, url, argv.scanId);
            await resourceTracker.setupTracking();
          }
          
          // Wait for page to load
          try {
            await page.waitForLoadState('networkidle', { timeout: 30000 });
          } catch (e) {
            logger.debug(`NetworkIdle timeout for ${url}, falling back to domcontentloaded`);
            await page.waitForLoadState('domcontentloaded', { timeout: 15000 });
          }
          
          await page.waitForTimeout(2000);
          
          if (crawleeConfig.contentExtraction?.waitForSelector) {
            try {
              await page.waitForSelector(crawleeConfig.contentExtraction.waitForSelector, {
                timeout: 5000
              });
            } catch (e) {
              logger.debug(`Selector wait timeout for ${url}`);
            }
          }
          
          // Get page content
          let html = '';
          try {
            html = await page.content();
          } catch (e) {
            logger.warn(`Failed to get content for ${url}, trying alternative method`);
            html = await page.evaluate(() => document.documentElement.outerHTML);
          }
          
          if (!html || html.length < 100) {
            throw new Error(`Content too short (${html.length} bytes)`);
          }
          
          // Save HTML with URL-based filename
          const htmlFilename = getFilenameForUrl(url, '.html');
          const htmlPath = path.join(dirs.html, htmlFilename);
          
          if (await saveContent(html, htmlPath)) {
            stats.htmlSaved++;
            addUrlMapping(htmlPath, url, 'html');
          }
          
          // Extract and save inline scripts
          const inlineScripts = extractInlineScripts(html);
          
          for (let i = 0; i < inlineScripts.length; i++) {
            const script = inlineScripts[i];
            
            // Generate filename for inline script
            const baseFilename = getFilenameForUrl(url, '');
            const scriptFilename = `${baseFilename}_inline_${i}.js`;
            const scriptPath = path.join(dirs.inlineScripts, scriptFilename);
            
            const finalContent = argv.beautify !== false
              ? beautify.js(script.content, { indent_size: 2 })
              : script.content;
            
            if (await saveContent(finalContent, scriptPath)) {
              stats.inlineScriptsSaved++;
              
              const inlineScriptUrl = `${url}#inline-script-${i}`;
              
              // Create resource info for inline script
              const inlineResourceInfo = {
                url: inlineScriptUrl,
                parentUrl: url,
                loadMethod: 'inline',
                loadTime: 0,
                resourceType: 'inline-script',
                scanId: argv.scanId,
                isThirdParty: false
              };
              
              addUrlMapping(scriptPath, inlineScriptUrl, 'inline-script', inlineResourceInfo);
              
              // Save metadata
              const inlineScriptMeta = {
                url: url,
                inline_script_url: inlineScriptUrl,
                type: 'inline_script',
                parent_url: url,
                script_index: i,
                timestamp: new Date().toISOString(),
                scanId: argv.scanId,
                has_potential_secrets: script.content.toLowerCase().includes('key') || 
                                      script.content.toLowerCase().includes('token') ||
                                      script.content.toLowerCase().includes('secret') ||
                                      script.content.toLowerCase().includes('password'),
                preciseMappingEnabled: argv.enablePreciseMapping
              };
              
              const metaFilename = `${baseFilename}_inline_${i}_meta.json`;
              const inlineMetaPath = path.join(dirs.metadata, metaFilename);
              await saveContent(JSON.stringify(inlineScriptMeta, null, 2), inlineMetaPath);
            }
          }
          
          // Extract JavaScript URLs
          const jsUrls = extractJavaScriptUrls(html, url);
          logger.debug(`Found ${jsUrls.length} JavaScript URLs in ${url}`);
          
          // Check for JSON content
          const contentType = response.headers()['content-type'] || '';
          if (contentType.includes('application/json')) {
            const jsonFilename = getFilenameForUrl(url, '.json');
            const jsonPath = path.join(dirs.json, jsonFilename);
            
            try {
              const responseBody = await response.text();
              const jsonData = JSON.parse(responseBody);
              const prettyJson = JSON.stringify(jsonData, null, 2);
              
              if (await saveContent(prettyJson, jsonPath)) {
                stats.jsonSaved++;
                addUrlMapping(jsonPath, url, 'json');
              }
            } catch (e) {
              logger.debug(`Failed to parse JSON from ${url}`);
            }
          }
          
          // Get resource relationships and dynamic loads
          let resourceRelationships = [];
          let dynamicLoads = {};
          
          if (resourceTracker) {
            resourceRelationships = resourceTracker.getResources();
            dynamicLoads = await resourceTracker.getDynamicLoads();
            
            logger.debug(`Tracked ${resourceRelationships.length} resources for ${url}`);
          }
          
          // Save enhanced metadata with resource relationships
          const metadata = {
            url,
            timestamp: new Date().toISOString(),
            statusCode: response.status(),
            headers: response.headers(),
            jsUrls,
            inlineScriptsCount: inlineScripts.length,
            contentLength: html.length,
            processingTime: Date.now() - startTime,
            attempt: request.retryCount + 1,
            scanId: argv.scanId,
            preciseMappingEnabled: argv.enablePreciseMapping
          };

          // Add resource relationship data if available
          if (argv.enablePreciseMapping && resourceTracker) {
            metadata.resourceRelationships = resourceRelationships;
            metadata.dynamicLoads = dynamicLoads;
            metadata.resourceTrackingStats = {
              totalResources: resourceRelationships.length,
              staticLoads: resourceRelationships.filter(r => r.loadMethod === 'static').length,
              dynamicLoads: resourceRelationships.filter(r => r.loadMethod === 'dynamic').length,
              dynamicChunks: resourceRelationships.filter(r => r.loadMethod === 'dynamic-chunk').length,
              thirdPartyResources: resourceRelationships.filter(r => r.isThirdParty).length,
              webpackChunks: resourceRelationships.filter(r => r.isWebpackChunk).length,
              nextJsChunks: resourceRelationships.filter(r => r.isNextJsChunk).length
            };
          }
          
          const metadataFilename = getFilenameForUrl(url, '_meta.json');
          const metadataPath = path.join(dirs.metadata, metadataFilename);
          await saveContent(JSON.stringify(metadata, null, 2), metadataPath);
          
          // Save per-page resource map
          if (argv.enablePreciseMapping && resourceRelationships.length > 0) {
            const resourceMapFilename = getFilenameForUrl(url, '_resources.json');
            const resourceMapPath = path.join(dirs.resourceMaps, resourceMapFilename);
            
            const resourceMapData = {
              pageUrl: url,
              scanId: argv.scanId,
              timestamp: new Date().toISOString(),
              resources: resourceRelationships,
              dynamicLoads: dynamicLoads,
              summary: {
                totalResources: resourceRelationships.length,
                byLoadMethod: {
                  static: resourceRelationships.filter(r => r.loadMethod === 'static').length,
                  dynamic: resourceRelationships.filter(r => r.loadMethod === 'dynamic').length,
                  dynamicChunk: resourceRelationships.filter(r => r.loadMethod === 'dynamic-chunk').length
                },
                byParty: {
                  firstParty: resourceRelationships.filter(r => !r.isThirdParty).length,
                  thirdParty: resourceRelationships.filter(r => r.isThirdParty).length
                },
                byType: {
                  webpackChunks: resourceRelationships.filter(r => r.isWebpackChunk).length,
                  nextJsChunks: resourceRelationships.filter(r => r.isNextJsChunk).length,
                  regularScripts: resourceRelationships.filter(r => !r.isWebpackChunk && !r.isNextJsChunk).length
                }
              }
            };
            
            await saveContent(JSON.stringify(resourceMapData, null, 2), resourceMapPath);
          }
          
          stats.urlsSuccessful++;
          logger.info(`✓ Successfully processed ${url} in ${Date.now() - startTime}ms`);
          
        } catch (error) {
          stats.errors++;
          stats.urlsFailed++;
          
          const errorInfo = {
            url,
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString(),
            attempt: request.retryCount + 1,
            processingTime: Date.now() - startTime,
            statusCode: response?.status(),
            scanId: argv.scanId
          };
          
          stats.failedUrls.push(url);
          stats.errorDetails[url] = errorInfo;
          
          const errorFilename = getFilenameForUrl(url, '_error.json');
          const errorPath = path.join(dirs.errors, errorFilename);
          await saveContent(JSON.stringify(errorInfo, null, 2), errorPath);
          
          logger.error(`✗ Failed ${url} after ${Date.now() - startTime}ms: ${error.message}`);
          
          throw error;
        }
      },
      
      failedRequestHandler: async ({ request, error }) => {
        logger.error(`Request completely failed for ${request.url}: ${error.message}`);
        
        const failedUrlsPath = path.join(outputDir, 'failed_urls.txt');
        await fs.appendFile(failedUrlsPath, `${request.url}\n`);
      }
    });
    
    // Process URLs in batches
    await processUrlBatch(urls, crawler);
    
    // Run the crawler
    logger.info('Starting crawler...');
    await crawler.run();
    
    // Save intercepted JavaScript files with enhanced metadata and fixed parent tracking
    logger.info(`Processing ${interceptedJsFiles.size} intercepted JavaScript files...`);
    
    for (const [jsUrl, jsData] of interceptedJsFiles) {
      const jsFilename = getFilenameForUrl(jsUrl, '.js');
      const jsPath = path.join(dirs.js, jsFilename);
      
      const finalContent = argv.beautify !== false
        ? beautify.js(jsData.content, { indent_size: 2 })
        : jsData.content;
      
      if (await saveContent(finalContent, jsPath)) {
        stats.jsSaved++;
        
        // Find corresponding resource relationship from ResourceTracker
        const resourceInfo = allResourceRelationships.find(r => r.url === jsUrl);
        
        // If no ResourceTracker data, create basic resource info from intercepted data
        if (!resourceInfo && jsData.fromPage && jsData.fromPage !== jsUrl) {
          const basicResourceInfo = {
            url: jsUrl,
            filename: jsFilename,
            parentUrl: jsData.fromPage,
            loadMethod: 'intercepted',
            loadTime: 0,
            resourceType: 'script',
            scanId: argv.scanId,
            isThirdParty: false,
            timestamp: jsData.timestamp
          };
          
          // Add to global relationships
          allResourceRelationships.push(basicResourceInfo);
          stats.resourceRelationships++;
          
          addUrlMapping(jsPath, jsUrl, 'javascript', basicResourceInfo);
        } else {
          addUrlMapping(jsPath, jsUrl, 'javascript', resourceInfo);
        }
        
        // Save enhanced JS metadata with correct parent page info
        const jsMetadata = {
          url: jsUrl,
          fromPage: jsData.fromPage,  // ✅ FIXED - now contains correct parent page URL
          headers: jsData.headers,
          size: jsData.content.length,
          timestamp: jsData.timestamp,
          scanId: jsData.scanId,
          interceptedDuringCrawl: jsData.interceptedDuringCrawl
        };

        // Add resource relationship data if available
        if (resourceInfo) {
          jsMetadata.parentUrl = resourceInfo.parentUrl;
          jsMetadata.loadMethod = resourceInfo.loadMethod;
          jsMetadata.loadTime = resourceInfo.loadTime;
          jsMetadata.isThirdParty = resourceInfo.isThirdParty;
          jsMetadata.isWebpackChunk = resourceInfo.isWebpackChunk;
          jsMetadata.isNextJsChunk = resourceInfo.isNextJsChunk;
          jsMetadata.preciseMappingEnabled = true;
        } else if (jsData.fromPage && jsData.fromPage !== jsUrl) {
          // Use intercepted data for basic mapping
          jsMetadata.parentUrl = jsData.fromPage;
          jsMetadata.loadMethod = 'intercepted';
          jsMetadata.preciseMappingEnabled = true;
        }
        
        const jsMetadataFilename = getFilenameForUrl(jsUrl, '_js_meta.json');
        const jsMetadataPath = path.join(dirs.metadata, jsMetadataFilename);
        await saveContent(JSON.stringify(jsMetadata, null, 2), jsMetadataPath);
      }
    }
    
    // Save URL mappings with resource relationships
    await saveUrlMappings(outputDir);
    
    // Save final statistics
    const duration = (Date.now() - stats.startTime) / 1000;
    stats.duration = duration;
    stats.successRate = stats.urlsProcessed > 0 
      ? ((stats.urlsSuccessful / stats.urlsProcessed) * 100).toFixed(2) + '%'
      : '0%';
    
    const statsPath = path.join(outputDir, 'crawler_stats.json');
    await saveContent(JSON.stringify(stats, null, 2), statsPath);
    
    // Save failed URLs summary
    if (stats.failedUrls.length > 0) {
      const failedSummaryPath = path.join(outputDir, 'failed_urls_summary.json');
      await saveContent(JSON.stringify({
        count: stats.failedUrls.length,
        urls: stats.failedUrls,
        details: stats.errorDetails
      }, null, 2), failedSummaryPath);
    }
    
    // Print summary
    logger.info('=== Enhanced Crawler Summary ===');
    logger.info(`Scan ID: ${argv.scanId}`);
    logger.info(`Precise URL Mapping: ${argv.enablePreciseMapping ? 'ENABLED' : 'DISABLED'}`);
    logger.info(`URLs processed: ${stats.urlsProcessed}`);
    logger.info(`Successful: ${stats.urlsSuccessful} (${stats.successRate})`);
    logger.info(`Failed: ${stats.urlsFailed}`);
    logger.info(`HTML files saved: ${stats.htmlSaved}`);
    logger.info(`JavaScript files saved: ${stats.jsSaved}`);
    logger.info(`Inline scripts saved: ${stats.inlineScriptsSaved}`);
    logger.info(`JSON files saved: ${stats.jsonSaved}`);
    logger.info(`Resource relationships tracked: ${stats.resourceRelationships}`);
    logger.info(`Precise mappings created: ${stats.preciseMappingsCreated}`);
    logger.info(`Errors: ${stats.errors}`);
    logger.info(`Duration: ${duration.toFixed(2)} seconds`);
    logger.info(`Output directory: ${outputDir}`);
    logger.info(`URL mappings saved: ${Object.keys(urlMappings.fileToUrl).length} files mapped`);
    
    if (stats.failedUrls.length > 0) {
      logger.warn(`Failed URLs: ${stats.failedUrls.length} (see failed_urls.txt)`);
    }
    
    if (argv.enablePreciseMapping) {
      logger.info(`✓ Enhanced precise URL mapping completed successfully`);
      logger.info(`✓ Resource relationship data saved to resource_relationships.json`);
      logger.info(`✓ Fixed parent page detection for JavaScript chunks`);
    }
    
  } catch (error) {
    logger.error(`Crawler failed: ${error.message}`);
    logger.error(error.stack);
    process.exit(1);
  }
}

// Error handling
process.on('unhandledRejection', (error) => {
  logger.error('Unhandled rejection:', error);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error);
  process.exit(1);
});

// Run the crawler
runCrawler()
  .then(() => {
    logger.info('Enhanced crawler completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Enhanced crawler failed:', error);
    process.exit(1);
  });