/**
 * Enhanced Crawlee-based Web Crawler for Secret Scanner
 * WITH URL MAPPING FUNCTIONALITY
 * 
 * This is the complete enhanced crawler.js file with URL mapping added.
 * Replace your existing crawler.js with this version.
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
if (argv.timeout > 300) {  // More than 5 minutes
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
  errorDetails: {}
};

// Intercepted JavaScript files
const interceptedJsFiles = new Map();

// URL MAPPING - NEW ADDITION
const urlMappings = {
  fileToUrl: {},      // Maps local file paths to original URLs
  urlToFile: {},      // Maps original URLs to local file paths
  metadata: {}        // Additional metadata for each mapping
};

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
  'other' // This catches things like favicons
];

/**
 * Generate a safe filename from a URL
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
 * Add URL mapping - NEW FUNCTION
 */
function addUrlMapping(localPath, originalUrl, contentType) {
  // Make path relative to output directory
  const relativePath = path.relative(argv.output, localPath).replace(/\\/g, '/');
  
  // Store bidirectional mapping
  urlMappings.fileToUrl[relativePath] = {
    url: originalUrl,
    contentType: contentType,
    timestamp: new Date().toISOString()
  };
  
  urlMappings.urlToFile[originalUrl] = relativePath;
  
  // Extract domain for metadata
  const urlObj = new URL(originalUrl);
  const domain = urlObj.hostname;
  
  if (!urlMappings.metadata[domain]) {
    urlMappings.metadata[domain] = {
      urls: [],
      files: []
    };
  }
  
  urlMappings.metadata[domain].urls.push(originalUrl);
  urlMappings.metadata[domain].files.push(relativePath);
  
  logger.debug(`Mapped: ${relativePath} -> ${originalUrl}`);
}

/**
 * Save URL mappings to file - NEW FUNCTION
 */
async function saveUrlMappings(outputDir) {
  const mappingPath = path.join(outputDir, 'url_mappings.json');
  const reverseMappingPath = path.join(outputDir, 'file_to_url_mappings.json');
  
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
    
    logger.info(`Saved URL mappings to ${mappingPath}`);
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
    // Skip empty scripts, comments, and external scripts
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
  // Skip data URLs
  if (url.startsWith('data:')) return false;
  
  // Skip blob URLs
  if (url.startsWith('blob:')) return false;
  
  // Check custom patterns
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
    
    // Add a small delay between batches to avoid overwhelming the target
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
    // Read URLs from input file
    logger.info(`Reading URLs from: ${argv.input}`);
    const urlsContent = await fs.readFile(argv.input, 'utf-8');
    const urls = urlsContent
      .split('\n')
      .map(url => url.trim())
      .filter(url => url && url.startsWith('http'))
      .filter(url => shouldProcessUrl(url));
    
    logger.info(`Found ${urls.length} URLs to process`);
    
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
      errors: path.join(outputDir, 'errors')
    };
    
    await Promise.all(Object.values(dirs).map(dir => fs.mkdir(dir, { recursive: true })));
    
    // Configure crawler
    const crawler = new PlaywrightCrawler({
      maxRequestsPerCrawl: argv.maxRequests,
      maxConcurrency: argv.concurrency,
      requestHandlerTimeoutSecs: argv.timeout,
      maxRequestRetries: 3,
      
      // Retry configuration
      retryOnBlocked: true,
      
      launchContext: {
        // launcher: crawleeConfig.playwright?.browserType || 'chromium',
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
          // Set timeouts
          const timeoutMs = argv.timeout * 1000;  // Convert seconds to milliseconds
          page.setDefaultNavigationTimeout(timeoutMs);
          page.setDefaultTimeout(timeoutMs);
          
          // Enhanced request interception
          await page.route('**/*', async (route) => {
            const request = route.request();
            const url = request.url();
            const resourceType = request.resourceType();
            
            // Check if domain is blocked
            const isBlockedDomain = BLOCKED_DOMAINS.some(domain => url.includes(domain));
            
            // Check if resource type is blocked
            const isBlockedType = BLOCKED_RESOURCE_TYPES.includes(resourceType);
            
            if (isBlockedDomain || isBlockedType) {
              await route.abort();
              return;
            }
            
            // Special handling for JavaScript files
            if (resourceType === 'script' || url.endsWith('.js')) {
              try {
                const response = await route.fetch();
                if (response.ok()) {
                  const content = await response.text();
                  if (content && content.length < 10 * 1024 * 1024) { // 10MB limit
                    interceptedJsFiles.set(url, {
                      content,
                      fromPage: request.url,
                      headers: response.headers()
                    });
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
        
        try {
          logger.info(`Processing: ${url} (attempt ${request.retryCount + 1})`);
          stats.urlsProcessed++;
          
          // Wait for page to load with multiple strategies
          try {
            await page.waitForLoadState('networkidle', { timeout: 30000 });
          } catch (e) {
            logger.debug(`NetworkIdle timeout for ${url}, falling back to domcontentloaded`);
            await page.waitForLoadState('domcontentloaded', { timeout: 15000 });
          }
          
          // Additional wait for dynamic content
          await page.waitForTimeout(2000);
          
          // Try to wait for specific content if configured
          if (crawleeConfig.contentExtraction?.waitForSelector) {
            try {
              await page.waitForSelector(crawleeConfig.contentExtraction.waitForSelector, {
                timeout: 5000
              });
            } catch (e) {
              logger.debug(`Selector wait timeout for ${url}`);
            }
          }
          
          // Get page content with fallback
          let html = '';
          try {
            html = await page.content();
          } catch (e) {
            logger.warn(`Failed to get content for ${url}, trying alternative method`);
            html = await page.evaluate(() => document.documentElement.outerHTML);
          }
          
          // Validate content
          if (!html || html.length < 100) {
            throw new Error(`Content too short (${html.length} bytes)`);
          }
          
          // Save HTML
          const htmlFilename = getSafeFilename(url, '.html');
          const htmlPath = path.join(dirs.html, htmlFilename);
          
          if (await saveContent(html, htmlPath)) {
            stats.htmlSaved++;
            // ADD URL MAPPING
            addUrlMapping(htmlPath, url, 'html');
          }
          
          // Extract and save inline scripts
          const inlineScripts = extractInlineScripts(html);
          
          for (let i = 0; i < inlineScripts.length; i++) {
            const script = inlineScripts[i];
            const scriptFilename = getSafeFilename(url, `_inline_${i}.js`);
            const scriptPath = path.join(dirs.inlineScripts, scriptFilename);
            
            const finalContent = argv.beautify !== false
              ? beautify.js(script.content, { indent_size: 2 })
              : script.content;
            
            if (await saveContent(finalContent, scriptPath)) {
              stats.inlineScriptsSaved++;
              
              // ADD URL MAPPING FOR INLINE SCRIPT
              const inlineScriptUrl = `${url}#inline-script-${i}`;
              addUrlMapping(scriptPath, inlineScriptUrl, 'inline-script');
              
              // Save inline script metadata with URL reference
              const inlineScriptMeta = {
                url: url,  // Original HTML page URL
                inline_script_url: inlineScriptUrl,  // Virtual URL for inline script
                type: 'inline_script',
                parent_url: url,
                script_index: i,
                timestamp: new Date().toISOString(),
                has_potential_secrets: script.content.toLowerCase().includes('key') || 
                                      script.content.toLowerCase().includes('token') ||
                                      script.content.toLowerCase().includes('secret') ||
                                      script.content.toLowerCase().includes('password')
              };
              
              const inlineMetaPath = path.join(dirs.metadata, getSafeFilename(`${url}_inline_${i}`, '_inline.json'));
              await saveContent(JSON.stringify(inlineScriptMeta, null, 2), inlineMetaPath);
            }
          }
          
          // Extract JavaScript URLs
          const jsUrls = extractJavaScriptUrls(html, url);
          logger.debug(`Found ${jsUrls.length} JavaScript URLs in ${url}`);
          
          // Check response headers for JSON content
          const contentType = response.headers()['content-type'] || '';
          if (contentType.includes('application/json')) {
            const jsonFilename = getSafeFilename(url, '.json');
            const jsonPath = path.join(dirs.json, jsonFilename);
            
            try {
              const responseBody = await response.text();
              // Try to pretty-print JSON
              const jsonData = JSON.parse(responseBody);
              const prettyJson = JSON.stringify(jsonData, null, 2);
              
              if (await saveContent(prettyJson, jsonPath)) {
                stats.jsonSaved++;
                // ADD URL MAPPING
                addUrlMapping(jsonPath, url, 'json');
              }
            } catch (e) {
              logger.debug(`Failed to parse JSON from ${url}`);
            }
          }
          
          // Save metadata
          const metadata = {
            url,
            timestamp: new Date().toISOString(),
            statusCode: response.status(),
            headers: response.headers(),
            jsUrls,
            inlineScriptsCount: inlineScripts.length,
            contentLength: html.length,
            processingTime: Date.now() - startTime,
            attempt: request.retryCount + 1
          };
          
          const metadataPath = path.join(dirs.metadata, getSafeFilename(url, '.json'));
          await saveContent(JSON.stringify(metadata, null, 2), metadataPath);
          
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
            statusCode: response?.status()
          };
          
          // Track failed URLs
          stats.failedUrls.push(url);
          stats.errorDetails[url] = errorInfo;
          
          const errorPath = path.join(dirs.errors, getSafeFilename(url, '.json'));
          await saveContent(JSON.stringify(errorInfo, null, 2), errorPath);
          
          logger.error(`✗ Failed ${url} after ${Date.now() - startTime}ms: ${error.message}`);
          
          // Re-throw to trigger retry
          throw error;
        }
      },
      
      failedRequestHandler: async ({ request, error }) => {
        logger.error(`Request completely failed for ${request.url}: ${error.message}`);
        
        // Save to failed URLs list
        const failedUrlsPath = path.join(outputDir, 'failed_urls.txt');
        await fs.appendFile(failedUrlsPath, `${request.url}\n`);
      }
    });
    
    // Process URLs in batches
    await processUrlBatch(urls, crawler);
    
    // Run the crawler
    logger.info('Starting crawler...');
    await crawler.run();
    
    // Save intercepted JavaScript files
    logger.info(`Processing ${interceptedJsFiles.size} intercepted JavaScript files...`);
    
    for (const [jsUrl, jsData] of interceptedJsFiles) {
      const jsFilename = getSafeFilename(jsUrl, '.js');
      const jsPath = path.join(dirs.js, jsFilename);
      
      const finalContent = argv.beautify !== false
        ? beautify.js(jsData.content, { indent_size: 2 })
        : jsData.content;
      
      if (await saveContent(finalContent, jsPath)) {
        stats.jsSaved++;
        
        // ADD URL MAPPING
        addUrlMapping(jsPath, jsUrl, 'javascript');
        
        // Save JS metadata
        const jsMetadata = {
          url: jsUrl,
          fromPage: jsData.fromPage,
          headers: jsData.headers,
          size: jsData.content.length,
          timestamp: new Date().toISOString()
        };
        
        const jsMetadataPath = path.join(dirs.metadata, getSafeFilename(jsUrl, '_js.json'));
        await saveContent(JSON.stringify(jsMetadata, null, 2), jsMetadataPath);
      }
    }
    
    // SAVE URL MAPPINGS - NEW ADDITION
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
    logger.info('=== Crawler Summary ===');
    logger.info(`URLs processed: ${stats.urlsProcessed}`);
    logger.info(`Successful: ${stats.urlsSuccessful} (${stats.successRate})`);
    logger.info(`Failed: ${stats.urlsFailed}`);
    logger.info(`HTML files saved: ${stats.htmlSaved}`);
    logger.info(`JavaScript files saved: ${stats.jsSaved}`);
    logger.info(`Inline scripts saved: ${stats.inlineScriptsSaved}`);
    logger.info(`JSON files saved: ${stats.jsonSaved}`);
    logger.info(`Errors: ${stats.errors}`);
    logger.info(`Duration: ${duration.toFixed(2)} seconds`);
    logger.info(`Output directory: ${outputDir}`);
    logger.info(`URL mappings saved: ${Object.keys(urlMappings.fileToUrl).length} files mapped`);
    
    if (stats.failedUrls.length > 0) {
      logger.warn(`Failed URLs: ${stats.failedUrls.length} (see failed_urls.txt)`);
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
    logger.info('Crawler completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Crawler failed:', error);
    process.exit(1);
  });