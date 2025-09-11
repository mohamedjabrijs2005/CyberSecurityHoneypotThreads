interface ActivityLog {
  type: string;
  email: string;
  password: string;
  ip: string;
  userAgent: string;
  timestamp: string;
}

// In-memory storage for demo purposes
let activityLogs: ActivityLog[] = [];

export const logSuspiciousActivity = (activity: ActivityLog) => {
  // Add to logs
  activityLogs.unshift({
    ...activity,
    timestamp: new Date().toLocaleTimeString()
  });

  // Keep only last 100 entries
  if (activityLogs.length > 100) {
    activityLogs = activityLogs.slice(0, 100);
  }

  // Simulate alert trigger for high-risk activities
  if (shouldTriggerAlert(activity)) {
    triggerMockAlert(activity);
  }

  console.log('🚨 Suspicious Activity Logged:', activity);
};

const shouldTriggerAlert = (activity: ActivityLog): boolean => {
  // Simple heuristics for demo
  const recentAttempts = activityLogs.filter(
    log => log.ip === activity.ip && 
    Date.now() - new Date(log.timestamp).getTime() < 300000 // 5 minutes
  ).length;

  return recentAttempts >= 3 || 
         activity.email.includes('admin') || 
         activity.password.length > 20;
};

const triggerMockAlert = (activity: ActivityLog) => {
  // Simulate SMS/WhatsApp alert
  console.log('📱 ALERT TRIGGERED:', {
    message: `Security Alert: Multiple failed login attempts from IP ${activity.ip}`,
    recipient: '+1234567890',
    service: 'SMS/WhatsApp',
    timestamp: new Date().toISOString()
  });
};

export const getActivityLogs = () => activityLogs;