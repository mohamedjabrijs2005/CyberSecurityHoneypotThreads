import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Users, 
  Globe,
  Bell,
  TrendingUp,
  Clock,
  MapPin,
  Smartphone
} from 'lucide-react';

const Dashboard: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Check backend connection
    const checkConnection = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/health');
        setIsConnected(response.ok);
      } catch (error) {
        setIsConnected(false);
      }
    };

    // Fetch real data from backend
    const fetchData = async () => {
      try {
        const [logsRes, statsRes, alertsRes] = await Promise.all([
          fetch('http://localhost:5000/api/logs'),
          fetch('http://localhost:5000/api/stats'),
          fetch('http://localhost:5000/api/alerts')
        ]);

        if (logsRes.ok) setLogs(await logsRes.json());
        if (statsRes.ok) setStats(await statsRes.json());
        if (alertsRes.ok) setAlerts(await alertsRes.json());
      } catch (error) {
        console.error('Failed to fetch data:', error);
        // Fallback to mock data if backend is not available
        const { getActivityLogs, getThreatStats, getRecentAlerts } = await import('../utils/mockData');
        setLogs(getActivityLogs());
        setStats(getThreatStats());
        setAlerts(getRecentAlerts());
      }
    };

    // Simulate real-time updates
    const interval = setInterval(() => {
      checkConnection();
      fetchData();
    }, 3000);

    // Initial load
    checkConnection();
    fetchData();

    return () => clearInterval(interval);
  }, []);

  const getThreatLevel = (level: string) => {
    const colors = {
      high: 'bg-red-100 text-red-800 border-red-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-green-100 text-green-800 border-green-200'
    };
    return colors[level as keyof typeof colors] || colors.low;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold">Honeypot Security Dashboard</h1>
              <p className="text-gray-400 text-sm">Real-time threat monitoring</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full ${
              isConnected ? 'bg-green-900' : 'bg-red-900'
            }`}>
              <div className={`w-2 h-2 rounded-full animate-pulse ${
                isConnected ? 'bg-green-400' : 'bg-red-400'
              }`}></div>
              <span className={`text-sm ${
                isConnected ? 'text-green-200' : 'text-red-200'
              }`}>
                {isConnected ? 'Backend Connected' : 'Backend Offline'}
              </span>
            </div>
            <Bell className="w-6 h-6 text-gray-400 hover:text-white cursor-pointer" />
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Attempts</p>
                <p className="text-2xl font-bold text-red-400">{stats.totalAttempts || 0}</p>
              </div>
              <Activity className="w-8 h-8 text-red-400" />
            </div>
            <div className="mt-2 flex items-center gap-1 text-sm">
              <TrendingUp className="w-4 h-4 text-red-400" />
              <span className="text-red-400">Live monitoring active</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Unique IPs</p>
                <p className="text-2xl font-bold text-yellow-400">{stats.uniqueIPs || 0}</p>
              </div>
              <Globe className="w-8 h-8 text-yellow-400" />
            </div>
            <div className="mt-2 flex items-center gap-1 text-sm">
              <MapPin className="w-4 h-4 text-yellow-400" />
              <span className="text-yellow-400">Geographic tracking</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Social Logins</p>
                <p className="text-2xl font-bold text-orange-400">{stats.socialLogins || 0}</p>
              </div>
              <Users className="w-8 h-8 text-orange-400" />
            </div>
            <div className="mt-2 flex items-center gap-1 text-sm">
              <Smartphone className="w-4 h-4 text-orange-400" />
              <span className="text-orange-400">OAuth attempts tracked</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">High Alerts</p>
                <p className="text-2xl font-bold text-purple-400">{stats.highAlerts || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-purple-400" />
            </div>
            <div className="mt-2 flex items-center gap-1 text-sm">
              <Clock className="w-4 h-4 text-purple-400" />
              <span className="text-purple-400">Last 24 hours</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Alerts */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-6 border-b border-gray-700">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Bell className="w-5 h-5" />
                Recent Alerts
              </h3>
            </div>
            <div className="p-6 space-y-4 max-h-96 overflow-y-auto">
              {alerts.map((alert, index) => (
                <div key={index} className="flex items-start gap-3 p-3 bg-gray-700 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-sm">{alert.title}</h4>
                      <span className={`px-2 py-1 rounded text-xs border ${getThreatLevel(alert.level)}`}>
                        {alert.level.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm mt-1">{alert.description}</p>
                    <p className="text-gray-500 text-xs mt-2">{alert.timestamp}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Activity Feed */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-6 border-b border-gray-700">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Activity className="w-5 h-5" />
                Live Activity Feed
              </h3>
            </div>
            <div className="p-6 space-y-3 max-h-96 overflow-y-auto">
              {logs.map((log, index) => (
                <div key={index} className="flex items-center gap-3 p-2 hover:bg-gray-700 rounded">
                  <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse flex-shrink-0"></div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{log.type}</span>
                      <span className="text-xs text-gray-400">{log.timestamp}</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                      {log.email} from {log.ip || 'unknown'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Mock Alert Integration Info */}
        <div className={`border rounded-lg p-6 ${
          isConnected ? 'bg-blue-900 border-blue-700' : 'bg-yellow-900 border-yellow-700'
        }`}>
          <div className="flex items-start gap-3">
            <Smartphone className={`w-6 h-6 flex-shrink-0 mt-0.5 ${
              isConnected ? 'text-blue-400' : 'text-yellow-400'
            }`} />
            <div>
              <h4 className={`font-semibold mb-2 ${
                isConnected ? 'text-blue-100' : 'text-yellow-100'
              }`}>
                {isConnected ? 'Backend Integration Active' : 'Backend Connection Required'}
              </h4>
              <p className={`text-sm mb-3 ${
                isConnected ? 'text-blue-200' : 'text-yellow-200'
              }`}>
                {isConnected 
                  ? 'Real-time logging and social OAuth tracking active. Production integrations:'
                  : 'Start the backend server to enable real-time logging and social login tracking.'
                }
              </p>
              {isConnected && (
                <ul className="text-blue-200 text-sm space-y-1">
                  <li>• Twilio API for SMS notifications</li>
                  <li>• WhatsApp Business API for instant messaging</li>
                  <li>• Google/LinkedIn/Facebook OAuth tracking</li>
                  <li>• Real-time threat detection and alerting</li>
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;