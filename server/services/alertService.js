const twilio = require('twilio');
require('dotenv').config();

class AlertService {
  constructor() {
    this.twilioClient = null;
    this.whatsappEnabled = false;
    this.smsEnabled = false;
    
    this.initializeTwilio();
    
    // Alert configuration
    this.alertConfig = {
      phoneNumber: process.env.ALERT_PHONE_NUMBER || '+1234567890',
      whatsappNumber: process.env.ALERT_WHATSAPP_NUMBER || 'whatsapp:+1234567890',
      enableSMS: process.env.ENABLE_SMS_ALERTS === 'true',
      enableWhatsApp: process.env.ENABLE_WHATSAPP_ALERTS === 'true',
      enableEmail: process.env.ENABLE_EMAIL_ALERTS === 'true',
      rateLimitMinutes: parseInt(process.env.ALERT_RATE_LIMIT_MINUTES) || 5
    };

    // Rate limiting for alerts
    this.lastAlertTimes = new Map();
  }

  initializeTwilio() {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    
    if (accountSid && authToken) {
      try {
        this.twilioClient = twilio(accountSid, authToken);
        this.smsEnabled = true;
        this.whatsappEnabled = true;
        console.log('✅ Twilio client initialized successfully');
      } catch (error) {
        console.error('❌ Failed to initialize Twilio client:', error.message);
      }
    } else {
      console.log('⚠️  Twilio credentials not configured - alerts will be logged only');
    }
  }

  async sendAlert(alertData) {
    const { title, description, severity, ip_address, email } = alertData;
    
    // Check rate limiting
    if (this.isRateLimited(ip_address)) {
      console.log(`🚫 Alert rate limited for IP: ${ip_address}`);
      return false;
    }

    const message = this.formatAlertMessage(alertData);
    const results = [];

    try {
      // Send SMS alert
      if (this.alertConfig.enableSMS && this.smsEnabled) {
        const smsResult = await this.sendSMS(message);
        results.push({ type: 'SMS', success: smsResult.success, id: smsResult.id });
      }

      // Send WhatsApp alert
      if (this.alertConfig.enableWhatsApp && this.whatsappEnabled) {
        const whatsappResult = await this.sendWhatsApp(message);
        results.push({ type: 'WhatsApp', success: whatsappResult.success, id: whatsappResult.id });
      }

      // Log alert (always enabled)
      this.logAlert(alertData, message);

      // Update rate limiting
      this.updateRateLimit(ip_address);

      console.log(`📱 Alert sent successfully:`, results);
      return { success: true, results };

    } catch (error) {
      console.error('❌ Failed to send alert:', error);
      return { success: false, error: error.message };
    }
  }

  async sendSMS(message) {
    if (!this.twilioClient) {
      return { success: false, error: 'Twilio not configured' };
    }

    try {
      const result = await this.twilioClient.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: this.alertConfig.phoneNumber
      });

      return { success: true, id: result.sid };
    } catch (error) {
      console.error('SMS send error:', error);
      return { success: false, error: error.message };
    }
  }

  async sendWhatsApp(message) {
    if (!this.twilioClient) {
      return { success: false, error: 'Twilio not configured' };
    }

    try {
      const result = await this.twilioClient.messages.create({
        body: message,
        from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
        to: this.alertConfig.whatsappNumber
      });

      return { success: true, id: result.sid };
    } catch (error) {
      console.error('WhatsApp send error:', error);
      return { success: false, error: error.message };
    }
  }

  formatAlertMessage(alertData) {
    const { title, description, severity, ip_address, email } = alertData;
    const timestamp = new Date().toLocaleString();
    
    const severityEmoji = {
      'high': '🚨',
      'medium': '⚠️',
      'low': 'ℹ️'
    };

    return `${severityEmoji[severity]} HONEYPOT ALERT

${title}

Details: ${description}
Severity: ${severity.toUpperCase()}
IP Address: ${ip_address || 'Unknown'}
Email: ${email || 'N/A'}
Time: ${timestamp}

This is an automated security alert from your honeypot system.`;
  }

  logAlert(alertData, message) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      alert: alertData,
      message: message,
      sent_via: []
    };

    if (this.alertConfig.enableSMS) logEntry.sent_via.push('SMS');
    if (this.alertConfig.enableWhatsApp) logEntry.sent_via.push('WhatsApp');

    console.log('📋 ALERT LOG:', JSON.stringify(logEntry, null, 2));
  }

  isRateLimited(ip_address) {
    const lastAlertTime = this.lastAlertTimes.get(ip_address);
    if (!lastAlertTime) return false;

    const timeDiff = Date.now() - lastAlertTime;
    const rateLimitMs = this.alertConfig.rateLimitMinutes * 60 * 1000;
    
    return timeDiff < rateLimitMs;
  }

  updateRateLimit(ip_address) {
    this.lastAlertTimes.set(ip_address, Date.now());
  }

  // Test alert functionality
  async sendTestAlert() {
    const testAlert = {
      title: 'Honeypot System Test Alert',
      description: 'This is a test alert to verify the notification system is working correctly.',
      severity: 'medium',
      ip_address: '192.168.1.100',
      email: 'test@example.com'
    };

    return await this.sendAlert(testAlert);
  }

  // Get alert statistics
  getAlertStats() {
    return {
      smsEnabled: this.smsEnabled,
      whatsappEnabled: this.whatsappEnabled,
      rateLimitMinutes: this.alertConfig.rateLimitMinutes,
      activeRateLimits: this.lastAlertTimes.size,
      twilioConfigured: !!this.twilioClient
    };
  }
}

module.exports = new AlertService();