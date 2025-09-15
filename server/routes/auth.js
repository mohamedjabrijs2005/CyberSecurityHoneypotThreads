const express = require('express');
const passport = require('passport');
const database = require('../config/database');
const threatAnalyzer = require('../services/threatAnalyzer');
const { rateLimiters, validationSchemas, handleValidationErrors } = require('../middleware/security');

const router = express.Router();

// Apply rate limiting to all auth routes
router.use(rateLimiters.login);

// Regular login endpoint (honeypot)
router.post('/login', validationSchemas.login, handleValidationErrors, async (req, res) => {
  const { email, password } = req.body;
  const ip_address = req.clientIP;
  const user_agent = req.get('User-Agent');
  
  try {
    // Log the activity
    const activityData = {
      type: 'Failed Login Attempt',
      email,
      password,
      ip_address,
      user_agent,
      success: false,
      payload: JSON.stringify(req.body)
    };

    // Log to database
    await database.logActivity(activityData);
    
    // Update IP tracking
    await database.updateIPTracking(ip_address, false);
    
    // Analyze for threats
    await threatAnalyzer.analyzeActivity(activityData);

    // Always return error after delay (honeypot behavior)
    setTimeout(() => {
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials. Please check your email and password.' 
      });
    }, 2000 + Math.random() * 1000); // Random delay 2-3 seconds

  } catch (error) {
    console.error('Login processing error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred. Please try again later.' 
    });
  }
});

// Google OAuth routes
router.get('/google', passport.authenticate('google', { 
  scope: ['profile', 'email'] 
}));

router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    // Log OAuth attempt
    const activityData = {
      type: 'Social Login Attempt - Google',
      email: req.user?.email || 'unknown',
      ip_address: req.clientIP,
      user_agent: req.get('User-Agent'),
      success: false, // Always false for honeypot
      provider: 'google',
      profile_id: req.user?.id,
      payload: JSON.stringify({
        profile: req.user,
        timestamp: new Date().toISOString()
      })
    };

    try {
      await database.logActivity(activityData);
      await threatAnalyzer.analyzeActivity(activityData);
    } catch (error) {
      console.error('OAuth logging error:', error);
    }

    // Redirect with error (honeypot behavior)
    res.redirect('http://localhost:5173?error=oauth_failed&provider=google');
  }
);

// LinkedIn OAuth routes
router.get('/linkedin', passport.authenticate('linkedin', {
  scope: ['r_emailaddress', 'r_liteprofile']
}));

router.get('/linkedin/callback',
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  async (req, res) => {
    const activityData = {
      type: 'Social Login Attempt - LinkedIn',
      email: req.user?.email || 'unknown',
      ip_address: req.clientIP,
      user_agent: req.get('User-Agent'),
      success: false,
      provider: 'linkedin',
      profile_id: req.user?.id,
      payload: JSON.stringify({
        profile: req.user,
        timestamp: new Date().toISOString()
      })
    };

    try {
      await database.logActivity(activityData);
      await threatAnalyzer.analyzeActivity(activityData);
    } catch (error) {
      console.error('OAuth logging error:', error);
    }

    res.redirect('http://localhost:5173?error=oauth_failed&provider=linkedin');
  }
);

// Facebook OAuth routes
router.get('/facebook', passport.authenticate('facebook', { 
  scope: ['email'] 
}));

router.get('/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  async (req, res) => {
    const activityData = {
      type: 'Social Login Attempt - Facebook',
      email: req.user?.email || 'unknown',
      ip_address: req.clientIP,
      user_agent: req.get('User-Agent'),
      success: false,
      provider: 'facebook',
      profile_id: req.user?.id,
      payload: JSON.stringify({
        profile: req.user,
        timestamp: new Date().toISOString()
      })
    };

    try {
      await database.logActivity(activityData);
      await threatAnalyzer.analyzeActivity(activityData);
    } catch (error) {
      console.error('OAuth logging error:', error);
    }

    res.redirect('http://localhost:5173?error=oauth_failed&provider=facebook');
  }
);

// Logout endpoint
router.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

module.exports = router;