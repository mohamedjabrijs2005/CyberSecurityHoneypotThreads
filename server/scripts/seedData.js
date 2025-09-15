const database = require('../config/database');
const bcrypt = require('bcrypt');

// Seed script for demo/test data
async function seedDatabase() {
  console.log('🌱 Seeding database with demo data...');

  try {
    // Create demo dashboard user
    const hashedPassword = await bcrypt.hash('admin123', 10);
    
    await new Promise((resolve, reject) => {
      database.db.run(`
        INSERT OR REPLACE INTO dashboard_users (username, password_hash, role)
        VALUES (?, ?, ?)
      `, ['admin', hashedPassword, 'admin'], function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });

    // Generate sample activity logs
    const sampleActivities = [
      {
        type: 'Failed Login Attempt',
        email: 'admin@company.com',
        password: 'password123',
        ip_address: '192.168.1.100',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        success: false,
        severity: 'high'
      },
      {
        type: 'SQL Injection Attempt',
        email: "admin' OR '1'='1",
        password: 'test',
        ip_address: '10.0.0.50',
        user_agent: 'curl/7.68.0',
        success: false,
        severity: 'high'
      },
      {
        type: 'Social Login Attempt - Google',
        email: 'user@gmail.com',
        ip_address: '203.0.113.45',
        user_agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
        success: false,
        provider: 'google',
        profile_id: 'google_123456789',
        severity: 'medium'
      },
      {
        type: 'Brute Force Attack',
        email: 'root@localhost',
        password: '123456',
        ip_address: '198.51.100.25',
        user_agent: 'python-requests/2.25.1',
        success: false,
        severity: 'high'
      },
      {
        type: 'Directory Traversal Attempt',
        email: '../../../etc/passwd',
        password: 'test',
        ip_address: '203.0.113.100',
        user_agent: 'Mozilla/5.0 (compatible; bot/1.0)',
        success: false,
        severity: 'medium'
      }
    ];

    // Insert sample activities
    for (const activity of sampleActivities) {
      await database.logActivity(activity);
      
      // Add some random delay to spread timestamps
      await new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
    }

    // Generate sample alerts
    const sampleAlerts = [
      {
        title: 'Multiple Failed Login Attempts',
        description: 'Detected 5 consecutive failed login attempts from IP 192.168.1.100',
        severity: 'high',
        reason_code: 'brute_force',
        ip_address: '192.168.1.100',
        email: 'admin@company.com'
      },
      {
        title: 'SQL Injection Attempt Detected',
        description: 'Malicious SQL patterns detected in login form submission',
        severity: 'high',
        reason_code: 'sql_injection',
        ip_address: '10.0.0.50',
        email: "admin' OR '1'='1"
      },
      {
        title: 'Suspicious Bot Activity',
        description: 'Automated scanning behavior detected from known bot user agent',
        severity: 'medium',
        reason_code: 'bot_scanning',
        ip_address: '203.0.113.100',
        email: null
      }
    ];

    // Insert sample alerts
    for (const alert of sampleAlerts) {
      await database.createAlert(alert);
    }

    // Update IP tracking for sample IPs
    const sampleIPs = ['192.168.1.100', '10.0.0.50', '203.0.113.45', '198.51.100.25'];
    for (const ip of sampleIPs) {
      await database.updateIPTracking(ip, false);
    }

    console.log('✅ Database seeded successfully with demo data');
    console.log('📊 Created:');
    console.log('   - 1 dashboard admin user (username: admin, password: admin123)');
    console.log('   - 5 sample activity logs');
    console.log('   - 3 sample alerts');
    console.log('   - IP tracking entries');

  } catch (error) {
    console.error('❌ Error seeding database:', error);
  }
}

// Run seeding if called directly
if (require.main === module) {
  seedDatabase().then(() => {
    process.exit(0);
  });
}

module.exports = { seedDatabase };