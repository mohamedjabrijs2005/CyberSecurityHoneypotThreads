import sqlite3 from 'sqlite3';
import path from 'path';

const dbPath = process.env.DATABASE_PATH || './honeypot.db';

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Could not connect to database', err.message);
  } else {
    console.log('✅ Connected to the honeypot database');
    initializeDatabase();
  }
});

const initializeDatabase = () => {
  const createTablesSQL = `
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      email TEXT,
      password TEXT, -- Note: Storing plaintext passwords is for honeypot purposes only!
      ip_address TEXT,
      user_agent TEXT,
      provider TEXT,
      profile_id TEXT,
      success BOOLEAN,
      severity TEXT DEFAULT 'low',
      payload TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      reason_code TEXT,
      ip_address TEXT,
      email TEXT,
      resolved BOOLEAN DEFAULT FALSE,
      alert_sent BOOLEAN DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS ip_tracking (
      ip_address TEXT PRIMARY KEY,
      first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      failed_attempts INTEGER DEFAULT 0,
      successful_attempts INTEGER DEFAULT 0,
      country TEXT,
      is_blacklisted BOOLEAN DEFAULT FALSE
    );
  `;
  
  db.exec(createTablesSQL, (err) => {
    if (err) {
      console.error('❌ Error creating tables:', err.message);
    } else {
      console.log('✔️  Database tables checked/created successfully');
    }
  });
};

const logActivity = (data) => {
  return new Promise((resolve, reject) => {
    const { 
      type, email, password, ip_address, user_agent, 
      provider, profile_id, success, severity, payload
    } = data;
    
    const sql = `
      INSERT INTO activity_logs 
      (type, email, password, ip_address, user_agent, provider, profile_id, success, severity, payload)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    db.run(sql, [
      type, email, password, ip_address, user_agent,
      provider, profile_id, success, severity, payload
    ], function(err) {
      if (err) {
        console.error('Database log error:', err);
        reject(err);
      } else {
        resolve({ id: this.lastID });
      }
    });
  });
};

const createAlert = (data) => {
  return new Promise((resolve, reject) => {
    const {
      title, description, severity, reason_code,
      ip_address, email
    } = data;

    const sql = `
      INSERT INTO alerts 
      (title, description, severity, reason_code, ip_address, email)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.run(sql, [title, description, severity, reason_code, ip_address, email], function(err) {
      if (err) {
        reject(err);
      } else {
        resolve(this.lastID);
      }
    });
  });
};

const getStats = () => {
  return new Promise((resolve, reject) => {
    const stats = {};
    db.get('SELECT COUNT(*) as total FROM activity_logs', (err, row) => {
      if (err) return reject(err);
      stats.total_events = row.total;
      
      db.get(`
        SELECT COUNT(*) as failed 
        FROM activity_logs 
        WHERE success = FALSE
      `, (err, row) => {
        if (err) return reject(err);
        stats.failed_logins = row.failed;
        
        db.get(`
          SELECT COUNT(DISTINCT ip_address) as unique_attackers 
          FROM activity_logs 
          WHERE success = FALSE
        `, (err, row) => {
          if (err) return reject(err);
          stats.unique_attackers = row.unique_attackers;
          resolve(stats);
        });
      });
    });
  });
};

const updateIPTracking = async (ip_address, success) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM ip_tracking WHERE ip_address = ?', [ip_address], (err, row) => {
      if (err) return reject(err);

      const updateSQL = success ? 
        `successful_attempts = successful_attempts + 1` : 
        `failed_attempts = failed_attempts + 1`;

      if (row) {
        // Update existing IP
        db.run(`
          UPDATE ip_tracking 
          SET last_seen = CURRENT_TIMESTAMP, ${updateSQL} 
          WHERE ip_address = ?
        `, [ip_address], (err) => {
          if (err) reject(err);
          else resolve();
        });
      } else {
        // Insert new IP
        db.run(`
          INSERT INTO ip_tracking 
          (ip_address, ${success ? 'successful_attempts' : 'failed_attempts'})
          VALUES (?, 1)
        `, [ip_address], (err) => {
          if (err) reject(err);
          else resolve();
        });
      }
    });
  });
};

const getActivityLogs = (limit = 50, offset = 0) => {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT * FROM activity_logs 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `, [limit, offset], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const getAlerts = (limit = 20, offset = 0) => {
  return new Promise((resolve, reject) => {
    db.all(`
      SELECT * FROM alerts 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `, [limit, offset], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const close = () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    } else {
      console.log('Database connection closed.');
    }
  });
};

export default {
  db,
  initializeDatabase,
  logActivity,
  createAlert,
  getStats,
  getActivityLogs,
  getAlerts,
  updateIPTracking,
  close
};
