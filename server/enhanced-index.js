const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const winston = require('winston');
const cron = require('node-cron');
require('dotenv').config();

// Import our modules
const database = require('./config/database');
const threatAnalyzer = require('./services/threatAnalyzer');
const alertService = require('./services/alertService');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const { 
  securityHeaders, 
  extractClientIP, 
  requestLogger, 
  detectSuspiciousActivity,
  corsOptions 
} = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 5000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'honeypot-backend' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security middleware
app.use(securityHeaders);
app.use(cors(corsOptions));
app.use(extractClientIP);
app.use(requestLogger);
app.use(detectSuspiciousActivity);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'honeypot-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // In a real app, you'd fetch from database
  done(null, { id });
});

// OAuth Strategies
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'demo-client-id',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'demo-client-secret',
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  // Log OAuth attempt
  const activityData = {
    type: 'Social Login Attempt - Google',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'google',
    profile_id: profile.id,
    success: false, // Always false for honeypot
    severity: 'medium'
  };

  try {
    await database.logActivity(activityData);
    await threatAnalyzer.analyzeActivity(activityData);
  } catch (error) {
    logger.error('OAuth logging error:', error);
  }

  return done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'google'
  });
}));

passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID || 'demo-client-id',
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET || 'demo-client-secret',
  callbackURL: "/auth/linkedin/callback",
  scope: ['r_emailaddress', 'r_liteprofile']
}, async (accessToken, refreshToken, profile, done) => {
  const activityData = {
    type: 'Social Login Attempt - LinkedIn',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'linkedin',
    profile_id: profile.id,
    success: false,
    severity: 'medium'
  };

  try {
    await database.logActivity(activityData);
    await threatAnalyzer.analyzeActivity(activityData);
  } catch (error) {
    logger.error('OAuth logging error:', error);
  }

  return done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'linkedin'
  });
}));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID || 'demo-app-id',
  clientSecret: process.env.FACEBOOK_APP_SECRET || 'demo-app-secret',
  callbackURL: "/auth/facebook/callback",
  profileFields: ['id', 'emails', 'name']
}, async (accessToken, refreshToken, profile, done) => {
  const activityData = {
    type: 'Social Login Attempt - Facebook',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'facebook',
    profile_id: profile.id,
    success: false,
    severity: 'medium'
  };

  try {
    await database.logActivity(activityData);
    await threatAnalyzer.analyzeActivity(activityData);
  } catch (error) {
    logger.error('OAuth logging error:', error);
  }

  return done(null, {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'facebook'
  });
}));

// Routes
app.use('/auth', authRoutes);
app.use('/api', apiRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Honeypot Security System API',
    version: '1.0.0',
    status: 'active',
    endpoints: {
      auth: '/auth/*',
      api: '/api/*',
      health: '/api/health'
    },
    documentation: 'See README.md for API documentation'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  // Log 404 attempts as potential reconnaissance
  const activityData = {
    type: 'Path Reconnaissance',
    ip_address: req.clientIP,
    user_agent: req.get('User-Agent'),
    payload: JSON.stringify({
      path: req.originalUrl,
      method: req.method,
      headers: req.headers
    }),
    success: false,
    severity: 'low'
  };

  database.logActivity(activityData).catch(err => {
    logger.error('Error logging 404:', err);
  });

  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// Scheduled tasks
// Clean up old logs (keep last 30 days)
cron.schedule('0 2 * * *', async () => {
  try {
    await new Promise((resolve, reject) => {
      database.db.run(`
        DELETE FROM activity_logs 
        WHERE created_at < datetime('now', '-30 days')
      `, function(err) {
        if (err) reject(err);
        else {
          logger.info(`Cleaned up ${this.changes} old activity logs`);
          resolve(this.changes);
        }
      });
    });

    await new Promise((resolve, reject) => {
      database.db.run(`
        DELETE FROM alerts 
        WHERE created_at < datetime('now', '-30 days') 
        AND resolved = TRUE
      `, function(err) {
        if (err) reject(err);
        else {
          logger.info(`Cleaned up ${this.changes} old resolved alerts`);
          resolve(this.changes);
        }
      });
    });
  } catch (error) {
    logger.error('Error during scheduled cleanup:', error);
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  database.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  database.close();
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  logger.info(`🚀 Enhanced Honeypot Backend Server running on port ${PORT}`);
  logger.info(`📊 Dashboard API available at http://localhost:${PORT}/api`);
  logger.info(`🔐 OAuth endpoints configured for social login tracking`);
  logger.info(`🛡️  Security middleware and threat analysis active`);
  logger.info(`📱 Alert service configured: ${alertService.getAlertStats().twilioConfigured ? 'Twilio Ready' : 'Demo Mode'}`);
  
  // Test database connection
  database.getStats().then(stats => {
    logger.info(`📈 Current stats: ${JSON.stringify(stats)}`);
  }).catch(err => {
    logger.error('Database connection test failed:', err);
  });
});

module.exports = app;