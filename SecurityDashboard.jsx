// 17th April
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Shield, AlertTriangle, Activity, FileWarning, Lock, Network, Flag } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

const SecurityDashboard = () => {
  const [metrics, setMetrics] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [threatData, setThreatData] = useState({
    malwareDetected: 0,
    suspiciousFiles: 0,
    blockedAttacks: 0,
    networkThreats: 0
  });
  const [securityScore, setSecurityScore] = useState(85);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchMetrics = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/security-metrics');
      
      if (!response.ok) {
        throw new Error(`Failed to fetch metrics: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'error') {
        throw new Error(data.message || 'Unknown error occurred');
      }
      
      setMetrics(data.metrics || []);
      setAlerts(data.alerts || []);
      setThreatData(data.threatData || {
        malwareDetected: 0,
        suspiciousFiles: 0,
        blockedAttacks: 0,
        networkThreats: 0
      });
      setSecurityScore(data.securityScore || 0);
      setError(null);
    } catch (error) {
      console.error('Error fetching security metrics:', error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const renderSecurityScore = () => (
    <Card className="w-full mb-4 bg-gradient-to-r from-gray-900 to-gray-800 text-white">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-cyan-400" />
          Threat Defense Score
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="text-4xl font-bold">
            {securityScore}%
          </div>
          <div className={`text-lg font-semibold ${
            securityScore > 80 ? 'text-green-400' :
            securityScore > 60 ? 'text-yellow-400' : 
            'text-red-400'
          }`}>
            {securityScore > 80 ? 'FORTRESS SECURE' :
             securityScore > 60 ? 'THREAT DETECTED' :
             'CRITICAL RISK'}
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const renderThreatMatrix = () => (
    <Card className="w-full mb-4 bg-gray-900 text-white">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          Threat Intelligence Matrix
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-gray-800 rounded-lg border border-red-800/30">
            <div className="flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-yellow-400" />
              <span>Ransomware</span>
            </div>
            <div className="text-2xl font-bold mt-2 text-red-400">
              {threatData.malwareDetected}
            </div>
          </div>
          <div className="p-4 bg-gray-800 rounded-lg border border-yellow-800/30">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <span>Suspicious Files</span>
            </div>
            <div className="text-2xl font-bold mt-2 text-yellow-400">
              {threatData.suspiciousFiles}
            </div>
          </div>
          <div className="p-4 bg-gray-800 rounded-lg border border-green-800/30">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-green-400" />
              <span>Blocked Attacks</span>
            </div>
            <div className="text-2xl font-bold mt-2 text-green-400">
              {threatData.blockedAttacks}
            </div>
          </div>
          <div className="p-4 bg-gray-800 rounded-lg border border-blue-800/30">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-400" />
              <span>Network Threats</span>
            </div>
            <div className="text-2xl font-bold mt-2 text-blue-400">
              {threatData.networkThreats}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const renderMetricsGraph = () => (
    <Card className="w-full mb-4 bg-gray-900 text-white">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          System Security Metrics
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="w-full h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={metrics}>
              <CartesianGrid strokeDasharray="3 3" stroke="#444" />
              <XAxis 
                dataKey="timestamp" 
                stroke="#fff" 
                tickFormatter={(time) => new Date(time).toLocaleTimeString()} 
              />
              <YAxis stroke="#fff" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: 'none', color: '#fff' }}
                labelFormatter={(time) => new Date(time).toLocaleString()} 
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="cpuUsage" 
                name="CPU Usage" 
                stroke="#8884d8" 
                strokeWidth={2} 
              />
              <Line 
                type="monotone" 
                dataKey="memoryUsage" 
                name="Memory Usage" 
                stroke="#82ca9d" 
                strokeWidth={2} 
              />
              <Line 
                type="monotone" 
                dataKey="networkActivity" 
                name="Network Activity" 
                stroke="#ffc658" 
                strokeWidth={2} 
                yAxisId={1}
                hide
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );

  const renderSecurityAlerts = () => (
    <Card className="w-full bg-gray-900 text-white">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Flag className="w-5 h-5 text-red-400" />
          Security Incident Log
        </CardTitle>
      </CardHeader>
      <CardContent>
        {alerts.length === 0 ? (
          <div className="text-center py-4 text-gray-400">
            No security alerts to display
          </div>
        ) : (
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {alerts.map((alert, index) => (
              <Alert 
                key={index} 
                className={`border-l-4 bg-gray-800 ${
                  alert.severity === 'critical' ? 'border-red-500' :
                  alert.severity === 'high' ? 'border-orange-500' :
                  alert.severity === 'medium' ? 'border-yellow-500' :
                  'border-green-500'
                }`}
              >
                <AlertDescription className="text-white">
                  <div className="flex items-center justify-between">
                    <span>{alert.message}</span>
                    <span className="text-sm text-gray-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );

  if (loading && metrics.length === 0) {
    return (
      <div className="min-h-screen bg-black p-6 flex items-center justify-center">
        <div className="text-white text-xl">Loading security metrics...</div>
      </div>
    );
  }

  if (error && metrics.length === 0) {
    return (
      <div className="min-h-screen bg-black p-6">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-3xl font-bold mb-6 text-white flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            Cybersecurity Command Center
          </h1>
          <Alert variant="destructive" className="mb-4">
            <AlertTriangle className="w-4 h-4" />
            <AlertDescription>Error loading security data: {error}</AlertDescription>
          </Alert>
          <button 
            onClick={fetchMetrics} 
            className="px-4 py-2 bg-cyan-500 text-white rounded hover:bg-cyan-600"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black p-6">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold mb-6 text-white flex items-center gap-2">
          <Shield className="w-8 h-8 text-cyan-400" />
          Cybersecurity Command Center
        </h1>
        <div className="grid grid-cols-1 gap-6">
          {renderSecurityScore()}
          {renderThreatMatrix()}
          {renderMetricsGraph()}
          {renderSecurityAlerts()}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;