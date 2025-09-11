// Mock data generators for demo purposes

let mockStats = {
  totalAttempts: 1247,
  uniqueIPs: 89,
  botTraffic: 73,
  highAlerts: 12,
  increase: 23,
  countries: 15
};

const generateMockIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

const generateMockEmail = () => {
  const domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'company.com', 'admin.local'];
  const users = ['admin', 'test', 'user', 'john.doe', 'administrator', 'root', 'guest'];
  return `${users[Math.floor(Math.random() * users.length)]}@${domains[Math.floor(Math.random() * domains.length)]}`;
};

const attackTypes = [
  'Brute Force Login',
  'SQL Injection Attempt',
  'XSS Probe',
  'Directory Traversal',
  'Bot Scanning',
  'Credential Stuffing',
  'Password Spraying'
];

const alertTitles = [
  'Multiple Failed Login Attempts',
  'Bot Traffic Detected',
  'Suspicious IP Activity',
  'Admin Account Targeted',
  'High-Frequency Requests',
  'Malicious Payload Detected',
  'Automated Scanning'
];

const alertDescriptions = [
  'Repeated login failures from single IP',
  'Non-human traffic patterns detected',
  'IP flagged in threat intelligence',
  'Attempts to access administrative accounts',
  'Request rate exceeds normal thresholds',
  'Known attack signatures in request',
  'Systematic probing of endpoints'
];

export const getThreatStats = () => {
  // Simulate slight increases over time
  mockStats.totalAttempts += Math.floor(Math.random() * 3);
  mockStats.uniqueIPs += Math.floor(Math.random() * 2);
  mockStats.botTraffic = Math.max(50, Math.min(95, mockStats.botTraffic + Math.floor(Math.random() * 3) - 1));
  
  return { ...mockStats };
};

export const getActivityLogs = () => {
  const logs = [];
  const now = new Date();
  
  for (let i = 0; i < 20; i++) {
    const timestamp = new Date(now.getTime() - (i * Math.random() * 300000)); // Last 5 hours
    logs.push({
      type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      email: generateMockEmail(),
      ip: generateMockIP(),
      timestamp: timestamp.toLocaleTimeString(),
      userAgent: 'Mozilla/5.0 (compatible; bot/1.0)'
    });
  }
  
  return logs;
};

export const getRecentAlerts = () => {
  const alerts = [];
  const now = new Date();
  
  for (let i = 0; i < 8; i++) {
    const timestamp = new Date(now.getTime() - (i * Math.random() * 3600000)); // Last hour
    const level = ['high', 'medium', 'low'][Math.floor(Math.random() * 3)];
    
    alerts.push({
      title: alertTitles[Math.floor(Math.random() * alertTitles.length)],
      description: alertDescriptions[Math.floor(Math.random() * alertDescriptions.length)],
      level,
      timestamp: timestamp.toLocaleString(),
      ip: generateMockIP()
    });
  }
  
  return alerts;
};