const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

// Rate limiting configurations
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({ error: message });
    }
  });
};

// Different rate limits for different endpoints
const rateLimiters = {
  // Strict rate limiting for login attempts (honeypot behavior)
  login: createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    10, // 10 attempts per window
    'Too many login attempts. Please try again later.'
  ),

  // Moderate rate limiting for API endpoints
  api: createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    100, // 100 requests per window
    'Too many API requests. Please try again later.'
  ),

  // Lenient rate limiting for dashboard
  dashboard: createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    200, // 200 requests per window
    'Too many dashboard requests. Please try again later.'
  )
};

// Input validation schemas
const validationSchemas = {
  login: [
    body('email')
      .isEmail()
      .normalizeEmail()
      .isLength({ max: 254 })
      .withMessage('Valid email is required'),
    body('password')
      .isLength({ min: 1, max: 128 })
      .withMessage('Password is required')
  ],

  dashboardAuth: [
    body('username')
      .isLength({ min: 3, max: 50 })
      .isAlphanumeric()
      .withMessage('Valid username is required'),
    body('password')
      .isLength({ min: 6, max: 128 })
      .withMessage('Password must be at least 6 characters')
  ]
};

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// Security headers configuration
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// IP extraction middleware
const extractClientIP = (req, res, next) => {
  // Get real IP address considering proxies
  const forwarded = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const remoteAddress = req.connection.remoteAddress || req.socket.remoteAddress;
  
  req.clientIP = forwarded ? forwarded.split(',')[0].trim() : 
                 realIP || 
                 remoteAddress || 
                 'unknown';
  
  next();
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log request
  console.log(`📥 ${req.method} ${req.path} - IP: ${req.clientIP} - UA: ${req.get('User-Agent')?.slice(0, 100)}`);
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    console.log(`📤 ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
};

// Suspicious activity detector
const detectSuspiciousActivity = (req, res, next) => {
  const suspiciousPatterns = [
    // Common attack patterns in URLs
    /\.\.[\/\\]/,
    /<script/i,
    /javascript:/i,
    /union.*select/i,
    /drop.*table/i,
    /exec\(/i,
    /eval\(/i
  ];

  const url = req.originalUrl;
  const userAgent = req.get('User-Agent') || '';
  const referer = req.get('Referer') || '';

  // Check for suspicious patterns
  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)
  );

  if (isSuspicious) {
    req.suspiciousActivity = {
      type: 'Suspicious Request Pattern',
      url,
      userAgent,
      referer,
      detected: true
    };
    
    console.log('🚨 Suspicious activity detected:', req.suspiciousActivity);
  }

  next();
};

// CORS configuration for honeypot
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests from frontend and common testing tools
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:3000'
    ];
    
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      // Log unauthorized origin attempts
      console.log(`🚫 Blocked CORS request from: ${origin}`);
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

module.exports = {
  rateLimiters,
  validationSchemas,
  handleValidationErrors,
  securityHeaders,
  extractClientIP,
  requestLogger,
  detectSuspiciousActivity,
  corsOptions
};