const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'honeypot-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// In-memory storage for demo (use database in production)
const users = [];
const activityLogs = [];
const alerts = [];

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'demo-client-id',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'demo-client-secret',
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  // Log suspicious social login attempt
  logSuspiciousActivity({
    type: 'Social Login Attempt - Google',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'google',
    profileId: profile.id,
    ip: 'unknown', // Will be set by middleware
    userAgent: 'OAuth Provider',
    timestamp: new Date().toISOString()
  });

  // In a real honeypot, we might create a fake user or redirect to error
  const user = {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'google'
  };
  
  users.push(user);
  return done(null, user);
}));

// LinkedIn OAuth Strategy
passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID || 'demo-client-id',
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET || 'demo-client-secret',
  callbackURL: "/auth/linkedin/callback",
  scope: ['r_emailaddress', 'r_liteprofile']
}, (accessToken, refreshToken, profile, done) => {
  logSuspiciousActivity({
    type: 'Social Login Attempt - LinkedIn',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'linkedin',
    profileId: profile.id,
    ip: 'unknown',
    userAgent: 'OAuth Provider',
    timestamp: new Date().toISOString()
  });

  const user = {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'linkedin'
  };
  
  users.push(user);
  return done(null, user);
}));

// Facebook OAuth Strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID || 'demo-app-id',
  clientSecret: process.env.FACEBOOK_APP_SECRET || 'demo-app-secret',
  callbackURL: "/auth/facebook/callback",
  profileFields: ['id', 'emails', 'name']
}, (accessToken, refreshToken, profile, done) => {
  logSuspiciousActivity({
    type: 'Social Login Attempt - Facebook',
    email: profile.emails?.[0]?.value || 'unknown',
    provider: 'facebook',
    profileId: profile.id,
    ip: 'unknown',
    userAgent: 'OAuth Provider',
    timestamp: new Date().toISOString()
  });

  const user = {
    id: profile.id,
    email: profile.emails?.[0]?.value,
    name: profile.displayName,
    provider: 'facebook'
  };
  
  users.push(user);
  return done(null, user);
}));

// Logging function
function logSuspiciousActivity(activity) {
  const logEntry = {
    ...activity,
    timestamp: new Date().toLocaleTimeString(),
    id: Date.now()
  };
  
  activityLogs.unshift(logEntry);
  
  // Keep only last 100 entries
  if (activityLogs.length > 100) {
    activityLogs.splice(100);
  }

  // Check if alert should be triggered
  if (shouldTriggerAlert(activity)) {
    const alert = {
      title: `Suspicious ${activity.provider || 'Login'} Activity`,
      description: `${activity.type} detected from ${activity.email}`,
      level: 'high',
      timestamp: new Date().toLocaleString(),
      ip: activity.ip || 'unknown'
    };
    alerts.unshift(alert);
    
    // Simulate SMS/WhatsApp alert
    console.log('🚨 ALERT TRIGGERED:', alert);
  }

  console.log('📝 Activity logged:', logEntry);
}

function shouldTriggerAlert(activity) {
  // Simple heuristics for demo
  return activity.type.includes('Social Login') || 
         activity.email.includes('admin') ||
         activity.type.includes('Failed Login');
}

// Routes

// Auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Redirect to frontend with error (honeypot behavior)
    res.redirect('http://localhost:5173?error=invalid_credentials');
  }
);

app.get('/auth/linkedin', passport.authenticate('linkedin'));
app.get('/auth/linkedin/callback',
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('http://localhost:5173?error=invalid_credentials');
  }
);

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('http://localhost:5173?error=invalid_credentials');
  }
);

// Regular login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;
  
  // Log all login attempts (this is a honeypot)
  logSuspiciousActivity({
    type: 'Failed Login Attempt',
    email,
    password: password.slice(0, 3) + '*'.repeat(Math.max(0, password.length - 3)),
    ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });

  // Always return error (honeypot behavior)
  setTimeout(() => {
    res.status(401).json({ 
      success: false, 
      message: 'Invalid credentials. Please try again.' 
    });
  }, 2000);
});

// Dashboard API endpoints
app.get('/api/logs', (req, res) => {
  res.json(activityLogs);
});

app.get('/api/alerts', (req, res) => {
  res.json(alerts);
});

app.get('/api/stats', (req, res) => {
  const stats = {
    totalAttempts: activityLogs.length,
    uniqueIPs: [...new Set(activityLogs.map(log => log.ip))].length,
    socialLogins: activityLogs.filter(log => log.type.includes('Social')).length,
    failedLogins: activityLogs.filter(log => log.type.includes('Failed')).length,
    highAlerts: alerts.filter(alert => alert.level === 'high').length
  };
  res.json(stats);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Honeypot backend server running on port ${PORT}`);
  console.log(`📊 Dashboard API available at http://localhost:${PORT}/api`);
  console.log(`🔐 OAuth endpoints configured for social login`);
});