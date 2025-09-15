const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
  constructor() {
    this.db = null;
    this.init();
  }

  init() {
    const dbPath = path.join(__dirname, '../data/honeypot.db');
    this.db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
      } else {
        console.log('Connected to SQLite database');
        this.createTables();
      }
    });
  }

  createTables() {
    // Activity logs table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        type TEXT NOT NULL,
        email TEXT,
        password_hash TEXT,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN DEFAULT FALSE,
        provider TEXT,
        profile_id TEXT,
        payload TEXT,
        severity TEXT DEFAULT 'low',
        country TEXT,
        city TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Alerts table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        reason_code TEXT,
        ip_address TEXT,
        email TEXT,
        alert_sent BOOLEAN DEFAULT FALSE,
        resolved BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // IP tracking table for behavioral analysis
    this.db.run(`
      CREATE TABLE IF NOT EXISTS ip_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        attempt_count INTEGER DEFAULT 1,
        failed_attempts INTEGER DEFAULT 0,
        success_attempts INTEGER DEFAULT 0,
        is_blocked BOOLEAN DEFAULT FALSE,
        country TEXT,
        city TEXT,
        threat_score INTEGER DEFAULT 0
      )
    `);

    // Dashboard users table (for admin access)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS dashboard_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables created successfully');
  }

  // Activity logging methods
  logActivity(data) {
    return new Promise((resolve, reject) => {
      const {
        type, email, password, ip_address, user_agent, 
        success = false, provider, profile_id, payload, severity = 'low'
      } = data;

      const stmt = this.db.prepare(`
        INSERT INTO activity_logs 
        (type, email, password_hash, ip_address, user_agent, success, provider, profile_id, payload, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      // Hash password for logging (first 3 chars + asterisks)
      const passwordHash = password ? password.slice(0, 3) + '*'.repeat(Math.max(0, password.length - 3)) : null;

      stmt.run([type, email, passwordHash, ip_address, user_agent, success, provider, profile_id, payload, severity], 
        function(err) {
          if (err) {
            reject(err);
          } else {
            resolve(this.lastID);
          }
        });
      stmt.finalize();
    });
  }

  // Get recent activity logs
  getActivityLogs(limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      this.db.all(`
        SELECT * FROM activity_logs 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
      `, [limit, offset], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  // Alert methods
  createAlert(data) {
    return new Promise((resolve, reject) => {
      const { title, description, severity, reason_code, ip_address, email } = data;
      
      const stmt = this.db.prepare(`
        INSERT INTO alerts (title, description, severity, reason_code, ip_address, email)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      stmt.run([title, description, severity, reason_code, ip_address, email], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
      stmt.finalize();
    });
  }

  // Get recent alerts
  getAlerts(limit = 20, offset = 0) {
    return new Promise((resolve, reject) => {
      this.db.all(`
        SELECT * FROM alerts 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
      `, [limit, offset], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      });
    });
  }

  // IP tracking methods
  updateIPTracking(ip_address, success = false) {
    return new Promise((resolve, reject) => {
      // First, try to update existing record
      this.db.run(`
        UPDATE ip_tracking 
        SET last_seen = CURRENT_TIMESTAMP,
            attempt_count = attempt_count + 1,
            failed_attempts = failed_attempts + ?,
            success_attempts = success_attempts + ?
        WHERE ip_address = ?
      `, [success ? 0 : 1, success ? 1 : 0, ip_address], function(err) {
        if (err) {
          reject(err);
        } else if (this.changes === 0) {
          // Insert new record if none exists
          const stmt = db.prepare(`
            INSERT INTO ip_tracking (ip_address, failed_attempts, success_attempts)
            VALUES (?, ?, ?)
          `);
          stmt.run([ip_address, success ? 0 : 1, success ? 1 : 0], function(err) {
            if (err) {
              reject(err);
            } else {
              resolve(this.lastID);
            }
          });
          stmt.finalize();
        } else {
          resolve(this.changes);
        }
      });
    });
  }

  // Get statistics
  getStats() {
    return new Promise((resolve, reject) => {
      const queries = [
        'SELECT COUNT(*) as total_attempts FROM activity_logs',
        'SELECT COUNT(DISTINCT ip_address) as unique_ips FROM activity_logs WHERE ip_address IS NOT NULL',
        'SELECT COUNT(*) as social_logins FROM activity_logs WHERE provider IS NOT NULL',
        'SELECT COUNT(*) as failed_logins FROM activity_logs WHERE success = FALSE',
        'SELECT COUNT(*) as high_alerts FROM alerts WHERE severity = "high"',
        'SELECT COUNT(*) as total_alerts FROM alerts',
        'SELECT COUNT(*) as recent_alerts FROM alerts WHERE created_at > datetime("now", "-24 hours")'
      ];

      Promise.all(queries.map(query => 
        new Promise((resolve, reject) => {
          this.db.get(query, (err, row) => {
            if (err) reject(err);
            else resolve(row);
          });
        })
      )).then(results => {
        resolve({
          totalAttempts: results[0].total_attempts || 0,
          uniqueIPs: results[1].unique_ips || 0,
          socialLogins: results[2].social_logins || 0,
          failedLogins: results[3].failed_logins || 0,
          highAlerts: results[4].high_alerts || 0,
          totalAlerts: results[5].total_alerts || 0,
          recentAlerts: results[6].recent_alerts || 0
        });
      }).catch(reject);
    });
  }

  close() {
    if (this.db) {
      this.db.close();
    }
  }
}

module.exports = new Database();