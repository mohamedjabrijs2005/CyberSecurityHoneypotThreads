const express = require('express');
const database = require('../config/database');
const alertService = require('../services/alertService');
const { rateLimiters } = require('../middleware/security');

const router = express.Router();

// Apply rate limiting to API routes
router.use(rateLimiters.api);

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Get activity logs with pagination
router.get('/logs', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100); // Max 100 per request
    const offset = (page - 1) * limit;

    const logs = await database.getActivityLogs(limit, offset);
    
    // Format logs for frontend
    const formattedLogs = logs.map(log => ({
      id: log.id,
      type: log.type,
      email: log.email,
      ip: log.ip_address,
      timestamp: new Date(log.created_at).toLocaleTimeString(),
      userAgent: log.user_agent,
      provider: log.provider,
      severity: log.severity,
      success: log.success
    }));

    res.json({
      success: true,
      data: formattedLogs,
      pagination: {
        page,
        limit,
        total: formattedLogs.length
      }
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch activity logs' 
    });
  }
});

// Get alerts with pagination
router.get('/alerts', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = (page - 1) * limit;

    const alerts = await database.getAlerts(limit, offset);
    
    // Format alerts for frontend
    const formattedAlerts = alerts.map(alert => ({
      id: alert.id,
      title: alert.title,
      description: alert.description,
      level: alert.severity,
      timestamp: new Date(alert.created_at).toLocaleString(),
      ip: alert.ip_address,
      email: alert.email,
      reasonCode: alert.reason_code,
      resolved: alert.resolved,
      alertSent: alert.alert_sent
    }));

    res.json({
      success: true,
      data: formattedAlerts,
      pagination: {
        page,
        limit,
        total: formattedAlerts.length
      }
    });
  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch alerts' 
    });
  }
});

// Get system statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = await database.getStats();
    const alertStats = alertService.getAlertStats();
    
    res.json({
      success: true,
      data: {
        ...stats,
        alerting: alertStats,
        lastUpdated: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch statistics' 
    });
  }
});

// Get live activity feed (recent entries)
router.get('/live-feed', async (req, res) => {
  try {
    const logs = await database.getActivityLogs(10, 0); // Last 10 entries
    
    const liveFeed = logs.map(log => ({
      id: log.id,
      type: log.type,
      email: log.email,
      ip: log.ip_address,
      timestamp: new Date(log.created_at).toLocaleTimeString(),
      severity: log.severity,
      provider: log.provider
    }));

    res.json({
      success: true,
      data: liveFeed,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching live feed:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch live feed' 
    });
  }
});

// Test alert endpoint (for testing purposes)
router.post('/test-alert', async (req, res) => {
  try {
    const result = await alertService.sendTestAlert();
    res.json({
      success: true,
      message: 'Test alert sent',
      result
    });
  } catch (error) {
    console.error('Error sending test alert:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send test alert' 
    });
  }
});

// Get threat analysis summary
router.get('/threat-analysis', async (req, res) => {
  try {
    // Get recent high-severity activities
    const recentThreats = await new Promise((resolve, reject) => {
      database.db.all(`
        SELECT type, severity, COUNT(*) as count, MAX(created_at) as last_seen
        FROM activity_logs 
        WHERE created_at > datetime('now', '-24 hours')
        AND severity IN ('high', 'medium')
        GROUP BY type, severity
        ORDER BY count DESC, last_seen DESC
      `, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    // Get top attacking IPs
    const topIPs = await new Promise((resolve, reject) => {
      database.db.all(`
        SELECT ip_address, COUNT(*) as attempts, 
               COUNT(CASE WHEN success = 0 THEN 1 END) as failed_attempts
        FROM activity_logs 
        WHERE created_at > datetime('now', '-24 hours')
        AND ip_address IS NOT NULL
        GROUP BY ip_address
        ORDER BY attempts DESC
        LIMIT 10
      `, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    res.json({
      success: true,
      data: {
        recentThreats,
        topAttackingIPs: topIPs,
        analysisTimestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error fetching threat analysis:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch threat analysis' 
    });
  }
});

// Mark alert as resolved
router.put('/alerts/:id/resolve', async (req, res) => {
  try {
    const alertId = parseInt(req.params.id);
    
    await new Promise((resolve, reject) => {
      database.db.run(`
        UPDATE alerts 
        SET resolved = TRUE 
        WHERE id = ?
      `, [alertId], function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });

    res.json({
      success: true,
      message: 'Alert marked as resolved'
    });
  } catch (error) {
    console.error('Error resolving alert:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to resolve alert' 
    });
  }
});

module.exports = router;