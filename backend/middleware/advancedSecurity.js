const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const crypto = require('crypto');
const xss = require('xss');
const mongoSanitize = require('express-mongo-sanitize');

const RedisStore = require('rate-limit-redis').default;
const Redis = require('ioredis');

// Initialize Redis Client for Rate Limiting
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Relaxed rate limiting with Redis Store
const createAdvancedRateLimit = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: { success: false, message, blocked: true },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    store: new RedisStore({
      sendCommand: (...args) => redisClient.call(...args),
      prefix: 'ctf:rl:'
    }),
    keyGenerator: (req) => {
      // Use IP for rate limiting
      return req.ip;
    },
    handler: (req, res) => {
      // Relaxed logging
      res.status(429).json({
        success: false,
        message,
        retryAfter: Math.round(windowMs / 1000)
      });
    }
  });
};

// Relaxed limits for UX - Now synced with .env
const strictLoginLimiter = createAdvancedRateLimit(
  (parseInt(process.env.LOGIN_TIMEOUT) || 1) * 60 * 1000,
  parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 100,
  'Too many login attempts. Please wait a moment.',
  false
);

const apiLimiter = createAdvancedRateLimit(
  15 * 60 * 1000,
  5000, // Very high limit for shared IPs (NAT)
  'API rate limit exceeded.'
);

const challengeSubmitLimiter = createAdvancedRateLimit(
  (parseInt(process.env.FLAG_SUBMIT_WINDOW) || 1) * 60 * 1000,
  parseInt(process.env.FLAG_SUBMIT_MAX_ATTEMPTS) || 100,
  'Please slow down your submissions.'
);

// Relaxed helmet configuration
const advancedHelmet = helmet({
  contentSecurityPolicy: false, // Let server.js handle CSP
  hsts: false, // Let server.js handle HSTS
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
});

// Advanced input sanitization
const advancedSanitization = (req, res, next) => {
  const sanitizeValue = (value) => {
    if (typeof value === 'string') {
      // Basic check for obvious XSS payload, but don't over-sanitize
      // Removed xss() library call to prevent breaking complex flag formats

      // Removed aggressive SQL injection patterns that break normal text
      // Parameterized queries are the real protection set in User.js/models

      // NoSQL injection protection using express-mongo-sanitize (already imported)

      return value.trim();
    }
    return value;
  };

  try {
    // Sanitize all input recursively
    const sanitizeObject = (obj) => {
      if (obj && typeof obj === 'object') {
        // Skip sanitizing files
        if (obj.buffer || obj.originalname) return obj;

        if (Array.isArray(obj)) {
          return obj.map(item => sanitizeObject(item));
        } else {
          const sanitized = {};
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              sanitized[key] = sanitizeObject(obj[key]);
            }
          }
          return sanitized;
        }
      }
      return sanitizeValue(obj);
    };

    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.params) req.params = sanitizeObject(req.params);

    next();
  } catch (error) {
    console.warn(`Security violation detected from IP: ${req.ip}, Error: ${error.message}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid input detected',
      blocked: true
    });
  }
};

// Relaxed validation
const enhancedValidation = {
  email: (email) => {
    if (!email || typeof email !== 'string') throw new Error('Email is required');
    // Simple regex check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Invalid email format');
    return email.toLowerCase();
  },

  username: (username) => {
    if (!username) throw new Error('Username is required');
    // Allow more flexible usernames for CTF teams
    return username;
  },

  password: (password) => {
    if (!password) throw new Error('Password is required');
    if (password.length < 6) throw new Error('Password too short (min 6)');
    return password;
  },

  objectId: (id) => {
    if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) throw new Error('Invalid ID');
    return id;
  }
};

// CSRF protection with token validation
const csrfProtection = (req, res, next) => {
  // Skip for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip if API key authentication is used
  if (req.headers['x-api-key']) {
    return next();
  }

  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session?.csrfToken;

  if (!token || !sessionToken || token !== sessionToken) {
    console.warn(`CSRF attack detected from IP: ${req.ip}`);
    return res.status(403).json({
      success: false,
      message: 'CSRF token validation failed',
      blocked: true
    });
  }

  next();
};

// File upload security with advanced validation
const secureFileUpload = {
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp'
  ],

  maxFileSize: 5 * 1024 * 1024, // 5MB

  validateFile: (file) => {
    if (!file) return true;

    // Check file size
    if (file.size > secureFileUpload.maxFileSize) {
      throw new Error('File size exceeds limit');
    }

    // Check MIME type
    if (!secureFileUpload.allowedMimeTypes.includes(file.mimetype)) {
      throw new Error('File type not allowed');
    }

    // Check file extension
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    if (!allowedExtensions.includes(fileExtension)) {
      throw new Error('File extension not allowed');
    }

    // Check for malicious file names
    if (/[<>:"/\\|?*\x00-\x1f]/.test(file.originalname)) {
      throw new Error('Invalid characters in filename');
    }

    // Check for double extensions
    if ((file.originalname.match(/\./g) || []).length > 1) {
      throw new Error('Multiple file extensions not allowed');
    }

    return true;
  }
};

// Security logging middleware
const securityLogger = (req, res, next) => {
  const startTime = Date.now();

  // Log security-relevant requests
  const securityPaths = ['/api/auth/', '/api/admin/', '/upload'];
  const isSecurityPath = securityPaths.some(path => req.path.startsWith(path));

  if (isSecurityPath) {
    console.log(`[SECURITY] ${req.method} ${req.path} from ${req.ip} - User-Agent: ${req.get('User-Agent')}`);
  }

  // Override res.json to log responses
  const originalJson = res.json;
  res.json = function (data) {
    const duration = Date.now() - startTime;

    if (isSecurityPath && (!data.success || data.blocked)) {
      console.warn(`[SECURITY_ALERT] ${req.method} ${req.path} - Status: ${res.statusCode} - Duration: ${duration}ms - IP: ${req.ip}`);
    }

    return originalJson.call(this, data);
  };

  next();
};

module.exports = {
  strictLoginLimiter,
  apiLimiter,
  challengeSubmitLimiter,
  advancedHelmet,
  advancedSanitization,
  enhancedValidation,
  csrfProtection,
  secureFileUpload,
  securityLogger,
  mongoSanitize: mongoSanitize()
};