const database = require('../config/database');
const alertService = require('./alertService');

class ThreatAnalyzer {
  constructor() {
    this.suspiciousPatterns = {
      sqlInjection: [
        /('|(\\')|(;)|(\\;)|(--)|(\s*(union|select|insert|delete|update|drop|create|alter|exec|execute)\s+)/i,
        /((\%27)|(\'))\s*((\%6F)|o|(\%4F))\s*((\%72)|r|(\%52))/i,
        /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i
      ],
      xssInjection: [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe[^>]*>.*?<\/iframe>/gi
      ],
      directoryTraversal: [
        /\.\.[\/\\]/g,
        /\%2e\%2e[\/\\]/gi,
        /\%252e\%252e[\/\\]/gi
      ],
      adminTargeting: [
        /admin/i,
        /administrator/i,
        /root/i,
        /superuser/i,
        /sa\b/i
      ]
    };

    this.threatScores = {
      'credential_stuffing': 8,
      'password_spraying': 7,
      'sql_injection': 9,
      'xss_attempt': 8,
      'directory_traversal': 7,
      'admin_targeting': 9,
      'bot_scanning': 6,
      'social_engineering': 8,
      'brute_force': 8
    };
  }

  async analyzeActivity(activityData) {
    const threats = [];
    const { type, email, password, ip_address, user_agent, payload } = activityData;

    // Check for SQL injection patterns
    if (this.detectSQLInjection(email, password, payload)) {
      threats.push({
        type: 'sql_injection',
        severity: 'high',
        reason: 'SQL injection patterns detected in input',
        score: this.threatScores.sql_injection
      });
    }

    // Check for XSS attempts
    if (this.detectXSSAttempt(email, password, payload)) {
      threats.push({
        type: 'xss_attempt',
        severity: 'high',
        reason: 'Cross-site scripting patterns detected',
        score: this.threatScores.xss_attempt
      });
    }

    // Check for directory traversal
    if (this.detectDirectoryTraversal(email, password, payload)) {
      threats.push({
        type: 'directory_traversal',
        severity: 'medium',
        reason: 'Directory traversal patterns detected',
        score: this.threatScores.directory_traversal
      });
    }

    // Check for admin account targeting
    if (this.detectAdminTargeting(email)) {
      threats.push({
        type: 'admin_targeting',
        severity: 'high',
        reason: 'Attempt to access administrative account',
        score: this.threatScores.admin_targeting
      });
    }

    // Check for credential stuffing/brute force
    const bruteForceCheck = await this.checkBruteForce(ip_address, email);
    if (bruteForceCheck.isThreat) {
      threats.push({
        type: bruteForceCheck.type,
        severity: bruteForceCheck.severity,
        reason: bruteForceCheck.reason,
        score: this.threatScores[bruteForceCheck.type]
      });
    }

    // Check for bot behavior
    const botCheck = this.detectBotBehavior(user_agent, ip_address);
    if (botCheck.isBot) {
      threats.push({
        type: 'bot_scanning',
        severity: 'medium',
        reason: botCheck.reason,
        score: this.threatScores.bot_scanning
      });
    }

    // Process threats and create alerts
    for (const threat of threats) {
      await this.processThreat(threat, activityData);
    }

    return threats;
  }

  detectSQLInjection(email, password, payload) {
    const inputs = [email, password, payload].filter(Boolean);
    return inputs.some(input => 
      this.suspiciousPatterns.sqlInjection.some(pattern => pattern.test(input))
    );
  }

  detectXSSAttempt(email, password, payload) {
    const inputs = [email, password, payload].filter(Boolean);
    return inputs.some(input => 
      this.suspiciousPatterns.xssInjection.some(pattern => pattern.test(input))
    );
  }

  detectDirectoryTraversal(email, password, payload) {
    const inputs = [email, password, payload].filter(Boolean);
    return inputs.some(input => 
      this.suspiciousPatterns.directoryTraversal.some(pattern => pattern.test(input))
    );
  }

  detectAdminTargeting(email) {
    if (!email) return false;
    return this.suspiciousPatterns.adminTargeting.some(pattern => pattern.test(email));
  }

  async checkBruteForce(ip_address, email) {
    try {
      // Get recent failed attempts from this IP
      const recentAttempts = await this.getRecentFailedAttempts(ip_address, 15); // Last 15 minutes
      const emailAttempts = await this.getRecentEmailAttempts(email, 30); // Last 30 minutes

      // Credential stuffing: Multiple different emails from same IP
      if (recentAttempts.length >= 5) {
        const uniqueEmails = new Set(recentAttempts.map(attempt => attempt.email));
        if (uniqueEmails.size >= 3) {
          return {
            isThreat: true,
            type: 'credential_stuffing',
            severity: 'high',
            reason: `${recentAttempts.length} failed attempts with ${uniqueEmails.size} different emails from IP ${ip_address}`
          };
        }
      }

      // Password spraying: Same email, multiple attempts
      if (emailAttempts.length >= 5) {
        return {
          isThreat: true,
          type: 'password_spraying',
          severity: 'high',
          reason: `${emailAttempts.length} failed attempts on email ${email}`
        };
      }

      // Brute force: High frequency from single IP
      if (recentAttempts.length >= 10) {
        return {
          isThreat: true,
          type: 'brute_force',
          severity: 'high',
          reason: `${recentAttempts.length} rapid failed attempts from IP ${ip_address}`
        };
      }

      return { isThreat: false };
    } catch (error) {
      console.error('Error checking brute force:', error);
      return { isThreat: false };
    }
  }

  detectBotBehavior(user_agent, ip_address) {
    if (!user_agent) {
      return { isBot: true, reason: 'Missing User-Agent header' };
    }

    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i,
      /automated/i, /script/i
    ];

    const suspiciousAgents = [
      'Mozilla/4.0', // Very old browser
      'Mozilla/5.0 (compatible;', // Generic bot signature
    ];

    // Check for bot patterns
    if (botPatterns.some(pattern => pattern.test(user_agent))) {
      return { isBot: true, reason: 'Bot-like User-Agent detected' };
    }

    // Check for suspicious agents
    if (suspiciousAgents.some(agent => user_agent.includes(agent))) {
      return { isBot: true, reason: 'Suspicious User-Agent pattern' };
    }

    // Check for very short or very long user agents
    if (user_agent.length < 20 || user_agent.length > 500) {
      return { isBot: true, reason: 'Abnormal User-Agent length' };
    }

    return { isBot: false };
  }

  async processThreat(threat, activityData) {
    const { ip_address, email } = activityData;
    
    // Create alert
    const alertData = {
      title: this.getThreatTitle(threat.type),
      description: threat.reason,
      severity: threat.severity,
      reason_code: threat.type,
      ip_address,
      email
    };

    const alertId = await database.createAlert(alertData);

    // Send notification for high-severity threats
    if (threat.severity === 'high') {
      await alertService.sendAlert(alertData);
    }

    console.log(`🚨 Threat detected: ${threat.type} (${threat.severity}) - ${threat.reason}`);
    return alertId;
  }

  getThreatTitle(threatType) {
    const titles = {
      'sql_injection': 'SQL Injection Attempt Detected',
      'xss_attempt': 'Cross-Site Scripting Attempt',
      'directory_traversal': 'Directory Traversal Attempt',
      'admin_targeting': 'Administrative Account Targeted',
      'credential_stuffing': 'Credential Stuffing Attack',
      'password_spraying': 'Password Spraying Attack',
      'brute_force': 'Brute Force Attack Detected',
      'bot_scanning': 'Automated Bot Scanning',
      'social_engineering': 'Social Engineering Attempt'
    };
    return titles[threatType] || 'Suspicious Activity Detected';
  }

  async getRecentFailedAttempts(ip_address, minutes = 15) {
    return new Promise((resolve, reject) => {
      database.db.all(`
        SELECT * FROM activity_logs 
        WHERE ip_address = ? 
        AND success = FALSE 
        AND created_at > datetime('now', '-${minutes} minutes')
        ORDER BY created_at DESC
      `, [ip_address], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }

  async getRecentEmailAttempts(email, minutes = 30) {
    return new Promise((resolve, reject) => {
      database.db.all(`
        SELECT * FROM activity_logs 
        WHERE email = ? 
        AND success = FALSE 
        AND created_at > datetime('now', '-${minutes} minutes')
        ORDER BY created_at DESC
      `, [email], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
  }
}

module.exports = new ThreatAnalyzer();