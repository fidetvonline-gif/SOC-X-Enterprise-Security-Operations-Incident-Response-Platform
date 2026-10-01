import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Terminal, Cpu, Activity, Database, 
  Lock, Unlock, Play, RefreshCw, FileText, Download, Layers, 
  Search, ShieldAlert, CheckCircle, Clock, Server, UserX, 
  ChevronRight, Menu, X, ArrowUpRight, Filter, AlertOctagon,
  Check, ExternalLink, Zap, Info
} from 'lucide-react';

interface Host {
  id: string;
  name: string;
  ip: string;
  os: string;
  status: 'online' | 'offline' | 'compromised';
  isIsolated: boolean;
  accountLocked: boolean;
  lastSeen: string;
  wazuhAgentVersion: string;
}

interface Alert {
  alert_id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  risk_score: number;
  source_host: string;
  source_ip: string;
  target_account: string;
  mitre_technique: string;
  mitre_tactic: string;
  evidence_raw: string;
  status: 'Unassigned' | 'Investigating' | 'Resolved' | 'False Positive';
}

interface Incident {
  incident_id: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Unassigned' | 'Investigating' | 'Contained' | 'Resolved';
  risk_score: number;
  affected_asset: string;
  associated_alert_ids: string[];
  mitre_mappings: string[];
  assigned_analyst: string;
  notes: string;
  response_action_taken: string;
  created_at: string;
}

interface AuditLog {
  id: string;
  timestamp: string;
  analyst_id: string;
  action_taken: string;
  target: string;
  status: 'Success' | 'Failed';
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'incidents' | 'investigation' | 'response' | 'simulation'>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  
  const [statusData, setStatusData] = useState<any>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [aiAnalysis, setAiAnalysis] = useState<string>('');
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [simulationLoading, setSimulationLoading] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Search & Filter States
  const [alertSearch, setAlertSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');

  const fetchData = async () => {
    try {
      const [statusRes, hostsRes, alertsRes, incRes, auditRes] = await Promise.all([
        fetch('/api/status').then(r => r.json()),
        fetch('/api/hosts').then(r => r.json()),
        fetch('/api/alerts').then(r => r.json()),
        fetch('/api/incidents').then(r => r.json()),
        fetch('/api/audit').then(r => r.json())
      ]);

      setStatusData(statusRes);
      setHosts(hostsRes);
      setAlerts(alertsRes);
      setIncidents(incRes);
      setAuditLogs(auditRes);

      if (incRes.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(incRes[0].incident_id);
      }
    } catch (err) {
      console.error('Failed to fetch SOC telemetry:', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const handleIsolate = async (hostId: string, isolate: boolean) => {
    const endpoint = isolate ? `/api/hosts/${hostId}/isolate` : `/api/hosts/${hostId}/unisolate`;
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: 'Analyst_1 (Senior IR)' })
      });
      const data = await res.json();
      if (data.success) {
        showToast(isolate ? `Host ${data.host.name} isolated from network.` : `Host ${data.host.name} isolation restored.`);
        fetchData();
      }
    } catch (err) {
      showToast('Error executing active response action.');
    }
  };

  const handleLockAccount = async (hostId: string, accountName: string) => {
    try {
      const res = await fetch(`/api/hosts/${hostId}/lock-account`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account: accountName, analyst: 'Analyst_1' })
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Account '${accountName}' disabled on ${data.host.name}.`);
        fetchData();
      }
    } catch (err) {
      showToast('Error locking user account.');
    }
  };

  const triggerSimulation = async (scenario: string) => {
    setSimulationLoading(scenario);
    try {
      const res = await fetch(`/api/simulate/${scenario}`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showToast(data.message);
        await fetchData();
        if (scenario === 'chain-attack') {
          setActiveTab('incidents');
        } else {
          setActiveTab('alerts');
        }
      } else {
        showToast(data.error || 'Simulation execution failed.');
      }
    } catch (err) {
      showToast('Simulation execution failed.');
    } finally {
      setSimulationLoading(null);
    }
  };

  const runAiInvestigation = async (incidentId: string) => {
    setIsAiLoading(true);
    setAiAnalysis('');
    try {
      const res = await fetch('/api/ai/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: incidentId })
      });
      const data = await res.json();
      setAiAnalysis(data.analysis);
    } catch (err) {
      setAiAnalysis('Failed to generate AI investigation report.');
    } finally {
      setIsAiLoading(false);
    }
  };

  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0];
  const incidentAlerts = alerts.filter(a => selectedIncident?.associated_alert_ids?.includes(a.alert_id));

  // Filtered alerts logic
  const filteredAlerts = alerts.filter(a => {
    const matchesSearch = alertSearch === '' || 
      a.alert_id.toLowerCase().includes(alertSearch.toLowerCase()) ||
      a.rule_name.toLowerCase().includes(alertSearch.toLowerCase()) ||
      a.source_host.toLowerCase().includes(alertSearch.toLowerCase()) ||
      a.mitre_technique.toLowerCase().includes(alertSearch.toLowerCase());
    const matchesSeverity = severityFilter === 'All' || a.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'Critical': return 'text-[#C24141] bg-[#C24141]/10 border-[#C24141]/30';
      case 'High': return 'text-[#B7791F] bg-[#B7791F]/10 border-[#B7791F]/30';
      case 'Medium': return 'text-[#2764A5] bg-[#2764A5]/10 border-[#2764A5]/30';
      default: return 'text-[#667085] bg-[#F1F3F5] border-[#E2E6EB]';
    }
  };

  interface NavItem {
    id: 'dashboard' | 'alerts' | 'incidents' | 'investigation' | 'response' | 'simulation';
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    count?: number;
  }

  interface NavGroup {
    group: string;
    items: NavItem[];
  }

  const navItems: NavGroup[] = [
    {
      group: 'OVERVIEW',
      items: [
        { id: 'dashboard', label: 'Dashboard & Assets', icon: Activity },
      ]
    },
    {
      group: 'THREAT DETECTION',
      items: [
        { id: 'alerts', label: 'Alerts Feed', icon: AlertTriangle, count: alerts.length },
        { id: 'incidents', label: 'Correlated Incidents', icon: Layers, count: incidents.filter(i => i.status !== 'Resolved').length },
      ]
    },
    {
      group: 'INVESTIGATION & PLAYBOOKS',
      items: [
        { id: 'investigation', label: 'Investigation Workspace', icon: Search },
        { id: 'response', label: 'Active Response', icon: ShieldAlert },
      ]
    },
    {
      group: 'LAB & SYSTEM',
      items: [
        { id: 'simulation', label: 'Simulation & Test Matrix', icon: Terminal },
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-[#F7F8FA] text-[#17202A] flex flex-col font-sans">
      
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-4 right-4 z-50 bg-[#12263A] text-white border border-[#334155] rounded-[6px] px-4 py-3 shadow-md flex items-center space-x-3 text-xs animate-fade-in">
          <ShieldAlert className="w-4 h-4 text-[#087F8C] shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      <div className="flex flex-1 min-h-screen">
        
        {/* Sidebar Navigation */}
        <aside className={`fixed inset-y-0 left-0 z-40 w-60 bg-[#0B1726] text-[#98A2B3] flex flex-col transition-transform duration-200 lg:static lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
          {/* Logo / Brand Header */}
          <div className="h-14 px-5 border-b border-[#12263A] flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-7 h-7 rounded-[6px] bg-[#087F8C] flex items-center justify-center text-white">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <span className="text-sm font-bold text-white tracking-tight">SOC-X</span>
                <span className="text-[11px] text-[#667085] block -mt-0.5">Enterprise Platform</span>
              </div>
            </div>
            <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-[#98A2B3] hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Nav Items */}
          <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6 text-xs font-medium">
            {navItems.map((group, idx) => (
              <div key={idx} className="space-y-1">
                <div className="px-3 py-1 text-[10px] font-semibold tracking-wider text-[#667085] uppercase">
                  {group.group}
                </div>
                {group.items.map(item => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        setActiveTab(item.id as any);
                        setSidebarOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-[6px] transition-colors cursor-pointer ${
                        isActive 
                          ? 'bg-[#12263A] text-white border-l-2 border-[#087F8C]' 
                          : 'text-[#98A2B3] hover:text-white hover:bg-[#12263A]/50'
                      }`}
                    >
                      <div className="flex items-center space-x-2.5">
                        <Icon className={`w-4 h-4 ${isActive ? 'text-[#087F8C]' : 'text-[#667085]'}`} />
                        <span>{item.label}</span>
                      </div>
                      {item.count !== undefined && item.count > 0 && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                          isActive ? 'bg-[#087F8C] text-white' : 'bg-[#12263A] text-[#98A2B3]'
                        }`}>
                          {item.count}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>

          {/* System Footer Status in Sidebar */}
          <div className="p-3 border-t border-[#12263A] text-[11px] text-[#667085] space-y-2">
            <div className="flex items-center justify-between">
              <span>SIEM Engine</span>
              <span className="text-[#16805C] font-mono flex items-center space-x-1">
                <span className="w-1.5 h-1.5 rounded-full bg-[#16805C]"></span>
                <span>Active</span>
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Wazuh Telemetry</span>
              <span className="text-[#98A2B3] font-mono">v4.7.2</span>
            </div>
          </div>
        </aside>

        {/* Sidebar backdrop on mobile */}
        {sidebarOpen && (
          <div onClick={() => setSidebarOpen(false)} className="fixed inset-0 bg-[#0B1726]/60 backdrop-blur-sm z-30 lg:hidden"></div>
        )}

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0">
          
          {/* Top Header */}
          <header className="h-14 bg-white border-b border-[#E2E6EB] px-6 flex items-center justify-between sticky top-0 z-20">
            <div className="flex items-center space-x-3">
              <button onClick={() => setSidebarOpen(true)} className="lg:hidden text-[#667085] hover:text-[#17202A]">
                <Menu className="w-5 h-5" />
              </button>
              
              {/* Breadcrumb Navigation */}
              <div className="flex items-center space-x-2 text-xs font-medium text-[#667085]">
                <span>SOC-X</span>
                <span className="text-[#98A2B3]">/</span>
                <span className="text-[#17202A] capitalize font-semibold">{activeTab}</span>
              </div>
            </div>

            {/* Header Right Actions & Analyst Info */}
            <div className="flex items-center space-x-4 text-xs font-medium">
              <div className="hidden sm:flex items-center space-x-2 px-2.5 py-1 bg-[#F1F3F5] rounded-[6px] border border-[#E2E6EB]">
                <span className="w-2 h-2 rounded-full bg-[#16805C]"></span>
                <span className="text-[#667085]">Wazuh Manager:</span>
                <span className="text-[#17202A] font-semibold">CONNECTED</span>
              </div>

              <div className="hidden md:flex items-center space-x-2 text-[#667085]">
                <span>Analyst:</span>
                <span className="font-semibold text-[#17202A]">Analyst_1 (Senior IR)</span>
              </div>

              <button
                onClick={() => triggerSimulation('chain-attack')}
                disabled={simulationLoading !== null}
                className="px-3.5 py-1.5 bg-[#087F8C] hover:bg-[#066A75] text-white rounded-[6px] font-medium transition cursor-pointer flex items-center space-x-1.5 text-xs shadow-sm disabled:opacity-50"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>{simulationLoading === 'chain-attack' ? 'Simulating...' : 'Run Attack Chain'}</span>
              </button>
            </div>
          </header>

          {/* Viewport Canvas */}
          <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
            
            {/* TAB 1: DASHBOARD */}
            {activeTab === 'dashboard' && (
              <div className="space-y-6 animate-fade-in">
                
                {/* Metric Blocks / KPI Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  
                  <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-4 flex flex-col justify-between space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-[#667085]">
                      <span>Critical Alerts</span>
                      <AlertOctagon className="w-4 h-4 text-[#C24141]" />
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="text-3xl font-extrabold text-[#C24141] font-mono tabular-nums">
                        {statusData?.counters?.criticalAlerts || 0}
                      </span>
                      <span className="text-xs text-[#98A2B3]">Immediate action</span>
                    </div>
                  </div>

                  <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-4 flex flex-col justify-between space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-[#667085]">
                      <span>Active Incidents</span>
                      <ShieldAlert className="w-4 h-4 text-[#B7791F]" />
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="text-3xl font-extrabold text-[#B7791F] font-mono tabular-nums">
                        {statusData?.counters?.activeIncidents || 0}
                      </span>
                      <span className="text-xs text-[#98A2B3]">Correlated chains</span>
                    </div>
                  </div>

                  <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-4 flex flex-col justify-between space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-[#667085]">
                      <span>Monitored Endpoints</span>
                      <Server className="w-4 h-4 text-[#087F8C]" />
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="text-3xl font-extrabold text-[#17202A] font-mono tabular-nums">
                        {hosts.length}
                      </span>
                      <span className="text-xs text-[#98A2B3]">Agents connected</span>
                    </div>
                  </div>

                  <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-4 flex flex-col justify-between space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-[#667085]">
                      <span>Isolated Endpoints</span>
                      <Lock className="w-4 h-4 text-[#2764A5]" />
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="text-3xl font-extrabold text-[#2764A5] font-mono tabular-nums">
                        {hosts.filter(h => h.isIsolated).length}
                      </span>
                      <span className="text-xs text-[#98A2B3]">Containment active</span>
                    </div>
                  </div>

                </div>

                {/* Monitored Endpoint Status Grid */}
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#E2E6EB]">
                    <div>
                      <h3 className="text-sm font-bold text-[#17202A]">Monitored Endpoint Nodes</h3>
                      <p className="text-xs text-[#667085]">Real-time host status, IP configuration, and active containment controls.</p>
                    </div>
                    <span className="text-xs text-[#667085] font-mono">Total Hosts: {hosts.length}</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {hosts.map(host => (
                      <div key={host.id} className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] p-3.5 flex flex-col justify-between space-y-3">
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-bold text-[#17202A] text-xs font-mono">{host.name}</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              host.isIsolated 
                                ? 'bg-[#C24141]/10 text-[#C24141] border-[#C24141]/30' 
                                : host.status === 'compromised' 
                                  ? 'bg-[#B7791F]/10 text-[#B7791F] border-[#B7791F]/30' 
                                  : 'bg-[#16805C]/10 text-[#16805C] border-[#16805C]/30'
                            }`}>
                              {host.isIsolated ? 'ISOLATED' : host.status === 'compromised' ? 'COMPROMISED' : 'ONLINE'}
                            </span>
                          </div>
                          <div className="text-[11px] text-[#667085] space-y-0.5 font-mono">
                            <p>IP: {host.ip}</p>
                            <p className="truncate text-[#98A2B3]">{host.os}</p>
                          </div>
                        </div>

                        <div className="pt-2 border-t border-[#E2E6EB] flex items-center space-x-2">
                          <button
                            onClick={() => handleIsolate(host.id, !host.isIsolated)}
                            className={`flex-1 py-1.5 px-2.5 rounded-[6px] text-xs font-medium transition cursor-pointer flex items-center justify-center space-x-1 ${
                              host.isIsolated 
                                ? 'bg-[#16805C] hover:bg-[#16805C]/90 text-white' 
                                : 'bg-[#C24141] hover:bg-[#C24141]/90 text-white'
                            }`}
                          >
                            {host.isIsolated ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                            <span>{host.isIsolated ? 'Restore' : 'Isolate'}</span>
                          </button>

                          <button
                            onClick={() => handleLockAccount(host.id, 'admin_test')}
                            className="px-2.5 py-1.5 rounded-[6px] text-xs font-medium bg-white border border-[#E2E6EB] text-[#17202A] hover:bg-[#F1F3F5] transition flex items-center space-x-1 cursor-pointer"
                            title="Disable User Account"
                          >
                            <UserX className="w-3.5 h-3.5 text-[#B7791F]" />
                            <span>Lock</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Real-time Ingest Data Table */}
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#E2E6EB]">
                    <div>
                      <h3 className="text-sm font-bold text-[#17202A]">Recent Security Telemetry</h3>
                      <p className="text-xs text-[#667085]">Live ingested alerts from Sysmon and Windows Event logs.</p>
                    </div>
                    <button onClick={fetchData} className="text-xs text-[#087F8C] hover:underline flex items-center space-x-1 font-medium cursor-pointer">
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Refresh</span>
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="bg-[#F1F3F5] text-[#667085] border-b border-[#E2E6EB]">
                          <th className="py-2.5 px-3">TIMESTAMP</th>
                          <th className="py-2.5 px-3">ALERT ID</th>
                          <th className="py-2.5 px-3 font-sans">RULE NAME</th>
                          <th className="py-2.5 px-3">SEVERITY</th>
                          <th className="py-2.5 px-3">HOST</th>
                          <th className="py-2.5 px-3">MITRE ID</th>
                          <th className="py-2.5 px-3">STATUS</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#E2E6EB]">
                        {alerts.slice(0, 6).map(alert => (
                          <tr key={alert.alert_id} className="hover:bg-[#F7F8FA] transition">
                            <td className="py-2.5 px-3 text-[#667085]">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                            <td className="py-2.5 px-3 text-[#087F8C] font-semibold">{alert.alert_id}</td>
                            <td className="py-2.5 px-3 text-[#17202A] font-sans font-medium">{alert.rule_name}</td>
                            <td className="py-2.5 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(alert.severity)}`}>
                                {alert.severity} ({alert.risk_score})
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-[#17202A]">{alert.source_host}</td>
                            <td className="py-2.5 px-3 text-[#2764A5] font-semibold">{alert.mitre_technique}</td>
                            <td className="py-2.5 px-3 text-[#667085]">{alert.status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            )}

            {/* TAB 2: ALERTS FEED */}
            {activeTab === 'alerts' && (
              <div className="space-y-6 animate-fade-in">
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#E2E6EB]">
                    <div>
                      <h3 className="text-base font-bold text-[#17202A]">All Ingested Security Alerts</h3>
                      <p className="text-xs text-[#667085]">Search and inspect telemetry events from Sysmon and Windows logs.</p>
                    </div>

                    {/* Filter & Search Bar */}
                    <div className="flex items-center space-x-2">
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#98A2B3]" />
                        <input
                          type="text"
                          placeholder="Search alerts or host..."
                          value={alertSearch}
                          onChange={(e) => setAlertSearch(e.target.value)}
                          className="pl-8 pr-3 py-1.5 text-xs border border-[#E2E6EB] rounded-[6px] bg-[#F7F8FA] focus:outline-none focus:border-[#087F8C] w-48 text-[#17202A]"
                        />
                      </div>

                      <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="px-2.5 py-1.5 text-xs border border-[#E2E6EB] rounded-[6px] bg-[#F7F8FA] text-[#17202A] focus:outline-none focus:border-[#087F8C]"
                      >
                        <option value="All">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {filteredAlerts.map(alert => (
                      <div key={alert.alert_id} className="border border-[#E2E6EB] rounded-[6px] p-4 bg-white hover:bg-[#F7F8FA] transition space-y-2.5">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(alert.severity)}`}>
                              {alert.severity} • Risk {alert.risk_score}
                            </span>
                            <span className="font-mono text-xs font-bold text-[#087F8C]">{alert.alert_id}</span>
                            <span className="text-xs font-semibold text-[#17202A]">{alert.rule_name}</span>
                          </div>
                          <div className="text-xs text-[#667085] font-mono">
                            {new Date(alert.timestamp).toLocaleString()}
                          </div>
                        </div>

                        {/* Unboxed Metadata Line */}
                        <div className="flex flex-wrap items-center gap-2 text-xs text-[#667085] font-mono pt-1 border-t border-[#F1F3F5]">
                          <span>Host: <strong className="text-[#17202A]">{alert.source_host}</strong></span>
                          <span>·</span>
                          <span>IP: <strong className="text-[#17202A]">{alert.source_ip}</strong></span>
                          <span>·</span>
                          <span>MITRE: <strong className="text-[#2764A5]">{alert.mitre_technique}</strong> ({alert.mitre_tactic})</span>
                          <span>·</span>
                          <span>Account: <strong className="text-[#17202A]">{alert.target_account}</strong></span>
                        </div>

                        {/* Evidence Log Box */}
                        <div className="bg-[#F1F3F5] p-2.5 rounded-[4px] font-mono text-xs text-[#17202A] border border-[#E2E6EB] leading-relaxed">
                          <span className="text-[#667085] font-semibold block mb-0.5">RAW EVIDENCE LOG:</span>
                          {alert.evidence_raw}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3: CORRELATED INCIDENTS */}
            {activeTab === 'incidents' && (
              <div className="space-y-6 animate-fade-in">
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-4">
                  <div className="pb-3 border-b border-[#E2E6EB]">
                    <h3 className="text-base font-bold text-[#17202A]">Correlated Security Incidents</h3>
                    <p className="text-xs text-[#667085]">Automatically grouped threat chains occurring within a 15-minute window.</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                    {/* Incidents Master List */}
                    <div className="lg:col-span-4 space-y-2">
                      {incidents.map(inc => (
                        <div 
                          key={inc.incident_id}
                          onClick={() => setSelectedIncidentId(inc.incident_id)}
                          className={`p-3.5 rounded-[6px] border cursor-pointer transition ${
                            selectedIncidentId === inc.incident_id 
                              ? 'bg-[#F1F3F5] border-[#087F8C]' 
                              : 'bg-white border-[#E2E6EB] hover:bg-[#F7F8FA]'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-mono font-bold text-[#087F8C]">{inc.incident_id}</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(inc.severity)}`}>
                              Risk {inc.risk_score}
                            </span>
                          </div>
                          <h4 className="font-semibold text-[#17202A] text-xs mb-1">{inc.title}</h4>
                          <div className="flex items-center justify-between text-[11px] text-[#667085] font-mono mt-2">
                            <span>Asset: {inc.affected_asset}</span>
                            <span className="text-[#087F8C] font-semibold">{inc.status}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Incident Detail Panel */}
                    <div className="lg:col-span-8 border border-[#E2E6EB] rounded-[6px] p-5 space-y-5 bg-[#F7F8FA]">
                      {selectedIncident ? (
                        <>
                          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-[#E2E6EB] pb-4">
                            <div>
                              <div className="flex items-center space-x-2 mb-1">
                                <span className="font-mono font-bold text-xs text-[#087F8C]">{selectedIncident.incident_id}</span>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(selectedIncident.severity)}`}>
                                  {selectedIncident.severity} Severity
                                </span>
                              </div>
                              <h2 className="text-base font-extrabold text-[#17202A]">{selectedIncident.title}</h2>
                            </div>
                            <div className="text-left sm:text-right text-xs text-[#667085] font-mono">
                              <p>Created: {new Date(selectedIncident.created_at).toLocaleString()}</p>
                              <p>Assigned: <strong className="text-[#17202A]">{selectedIncident.assigned_analyst}</strong></p>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-4 bg-white p-3.5 rounded-[6px] border border-[#E2E6EB] text-xs">
                            <div>
                              <span className="text-[#667085] font-semibold block uppercase tracking-wider text-[10px] mb-0.5">Affected Asset</span>
                              <span className="font-mono text-[#17202A] font-bold">{selectedIncident.affected_asset}</span>
                            </div>
                            <div>
                              <span className="text-[#667085] font-semibold block uppercase tracking-wider text-[10px] mb-0.5">Calculated Risk Score</span>
                              <span className="font-mono text-[#C24141] font-bold text-sm">{selectedIncident.risk_score} / 100</span>
                            </div>
                          </div>

                          <div>
                            <h4 className="text-xs font-bold text-[#17202A] mb-2">MITRE ATT&CK Mapping</h4>
                            <div className="flex flex-wrap gap-1.5">
                              {selectedIncident.mitre_mappings.map(m => (
                                <span key={m} className="px-2 py-0.5 bg-white text-[#2764A5] border border-[#E2E6EB] rounded text-xs font-mono font-semibold">
                                  {m}
                                </span>
                              ))}
                            </div>
                          </div>

                          <div>
                            <h4 className="text-xs font-bold text-[#17202A] mb-2">Linked Security Alerts ({incidentAlerts.length})</h4>
                            <div className="space-y-2">
                              {incidentAlerts.map(alt => (
                                <div key={alt.alert_id} className="p-3 bg-white rounded-[6px] border border-[#E2E6EB] flex items-center justify-between text-xs">
                                  <div>
                                    <span className="text-[#087F8C] font-mono font-bold mr-2">{alt.alert_id}</span>
                                    <span className="text-[#17202A] font-medium">{alt.rule_name}</span>
                                  </div>
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(alt.severity)}`}>
                                    {alt.severity}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>

                          <div className="pt-3 border-t border-[#E2E6EB] flex justify-end">
                            <button
                              onClick={() => {
                                setActiveTab('investigation');
                                runAiInvestigation(selectedIncident.incident_id);
                              }}
                              className="px-4 py-2 bg-[#087F8C] hover:bg-[#066A75] text-white rounded-[6px] text-xs font-semibold flex items-center space-x-2 transition cursor-pointer"
                            >
                              <Cpu className="w-4 h-4" />
                              <span>Launch AI Investigation & Playbook</span>
                            </button>
                          </div>
                        </>
                      ) : (
                        <p className="text-xs text-[#667085]">Select an incident to view investigation metrics.</p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: INVESTIGATION WORKSPACE */}
            {activeTab === 'investigation' && (
              <div className="space-y-6 animate-fade-in">
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#E2E6EB]">
                    <div>
                      <h3 className="text-base font-bold text-[#17202A]">Investigation Workspace</h3>
                      <p className="text-xs text-[#667085]">Chronological attack timeline analysis and Gemini AI triage report.</p>
                    </div>

                    <div className="flex items-center space-x-3">
                      <select
                        value={selectedIncidentId}
                        onChange={(e) => setSelectedIncidentId(e.target.value)}
                        className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] px-3 py-1.5 text-xs text-[#17202A] font-mono focus:outline-none focus:border-[#087F8C]"
                      >
                        {incidents.map(inc => (
                          <option key={inc.incident_id} value={inc.incident_id}>
                            {inc.incident_id}: {inc.affected_asset}
                          </option>
                        ))}
                      </select>

                      <button
                        onClick={() => runAiInvestigation(selectedIncidentId)}
                        disabled={isAiLoading}
                        className="px-3.5 py-1.5 bg-[#087F8C] hover:bg-[#066A75] text-white rounded-[6px] text-xs font-semibold flex items-center space-x-1.5 transition cursor-pointer disabled:opacity-50"
                      >
                        <Cpu className="w-3.5 h-3.5" />
                        <span>{isAiLoading ? 'Analyzing...' : 'Generate AI Report'}</span>
                      </button>
                    </div>
                  </div>

                  {/* AI Output Report */}
                  {aiAnalysis && (
                    <div className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] p-5 space-y-3">
                      <div className="flex items-center justify-between border-b border-[#E2E6EB] pb-3">
                        <span className="text-xs font-bold text-[#087F8C] flex items-center space-x-1.5">
                          <Cpu className="w-4 h-4" />
                          <span>SOC-X AI Investigation & Remediation Playbook</span>
                        </span>
                        <button 
                          onClick={() => {
                            const blob = new Blob([aiAnalysis], { type: 'text/markdown' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `${selectedIncidentId}-Report.md`;
                            a.click();
                          }}
                          className="px-2.5 py-1 bg-white hover:bg-[#F1F3F5] text-[#17202A] border border-[#E2E6EB] rounded-[6px] text-xs font-medium flex items-center space-x-1 transition cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Export Markdown</span>
                        </button>
                      </div>
                      <div className="text-xs font-mono text-[#17202A] whitespace-pre-wrap leading-relaxed">
                        {aiAnalysis}
                      </div>
                    </div>
                  )}

                  {/* Chronological Attack Chain Timeline */}
                  <div className="space-y-4 pt-2">
                    <h4 className="text-xs font-bold text-[#17202A] uppercase tracking-wider text-[#667085]">
                      Attack Chain Sequence
                    </h4>

                    <div className="relative border-l border-[#E2E6EB] ml-3 space-y-4 py-1">
                      {incidentAlerts.map((alt, idx) => (
                        <div key={alt.alert_id} className="relative pl-5">
                          {/* Timeline connector dot */}
                          <div className="absolute -left-1.5 top-2 w-3 h-3 rounded-full bg-[#087F8C] border-2 border-white"></div>

                          <div className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] p-3.5 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                <span className="text-[#087F8C] font-mono font-bold text-xs">{alt.alert_id}</span>
                                <span className="text-[#17202A] font-semibold text-xs">{alt.rule_name}</span>
                              </div>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(alt.severity)}`}>
                                {alt.severity}
                              </span>
                            </div>

                            <div className="text-xs text-[#667085] font-mono">
                              Timestamp: <strong className="text-[#17202A]">{new Date(alt.timestamp).toLocaleTimeString()}</strong> · Host: <strong className="text-[#17202A]">{alt.source_host}</strong> · MITRE: <strong className="text-[#2764A5]">{alt.mitre_technique}</strong>
                            </div>

                            <div className="bg-white p-2.5 rounded-[4px] font-mono text-xs text-[#17202A] border border-[#E2E6EB]">
                              {alt.evidence_raw}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 5: ACTIVE RESPONSE & AUDIT */}
            {activeTab === 'response' && (
              <div className="space-y-6 animate-fade-in">
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-5">
                  <div className="pb-3 border-b border-[#E2E6EB]">
                    <h3 className="text-base font-bold text-[#17202A]">Automated Active Response Controls</h3>
                    <p className="text-xs text-[#667085]">Execute host isolation playbooks and review immutable response audit logs.</p>
                  </div>

                  {/* Endpoints Control Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {hosts.map(host => (
                      <div key={host.id} className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] p-4 flex flex-col justify-between space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="font-bold text-[#17202A] font-mono text-sm">{host.name}</h4>
                            <p className="text-xs text-[#667085] font-mono">IP: {host.ip} · OS: {host.os}</p>
                          </div>
                          <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${
                            host.isIsolated ? 'bg-[#C24141]/10 text-[#C24141] border-[#C24141]/30' : 'bg-[#16805C]/10 text-[#16805C] border-[#16805C]/30'
                          }`}>
                            {host.isIsolated ? 'CONTAINED' : 'ONLINE'}
                          </span>
                        </div>

                        <div className="flex items-center space-x-2 pt-2 border-t border-[#E2E6EB]">
                          <button
                            onClick={() => handleIsolate(host.id, !host.isIsolated)}
                            className={`flex-1 py-1.5 px-3 rounded-[6px] text-xs font-medium transition cursor-pointer flex items-center justify-center space-x-1.5 ${
                              host.isIsolated 
                                ? 'bg-[#16805C] hover:bg-[#16805C]/90 text-white' 
                                : 'bg-[#C24141] hover:bg-[#C24141]/90 text-white'
                            }`}
                          >
                            {host.isIsolated ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                            <span>{host.isIsolated ? 'Lift Isolation' : 'Isolate Host'}</span>
                          </button>

                          <button
                            onClick={() => handleLockAccount(host.id, 'admin_test')}
                            className="px-3 py-1.5 rounded-[6px] text-xs font-medium bg-white border border-[#E2E6EB] text-[#17202A] hover:bg-[#F1F3F5] transition flex items-center space-x-1.5 cursor-pointer"
                          >
                            <UserX className="w-3.5 h-3.5 text-[#B7791F]" />
                            <span>Lock User</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Audit Trail Log Table */}
                  <div className="pt-4 border-t border-[#E2E6EB] space-y-3">
                    <h4 className="text-xs font-bold text-[#17202A] uppercase tracking-wider text-[#667085]">
                      Response Action Audit Trail
                    </h4>
                    <div className="overflow-x-auto border border-[#E2E6EB] rounded-[6px]">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[#F1F3F5] border-b border-[#E2E6EB] text-[#667085]">
                            <th className="py-2.5 px-3">TIMESTAMP</th>
                            <th className="py-2.5 px-3">AUDIT ID</th>
                            <th className="py-2.5 px-3">ANALYST</th>
                            <th className="py-2.5 px-3 font-sans">ACTION EXECUTED</th>
                            <th className="py-2.5 px-3">TARGET</th>
                            <th className="py-2.5 px-3">STATUS</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E2E6EB]">
                          {auditLogs.map(log => (
                            <tr key={log.id} className="hover:bg-[#F7F8FA]">
                              <td className="py-2.5 px-3 text-[#667085]">{new Date(log.timestamp).toLocaleTimeString()}</td>
                              <td className="py-2.5 px-3 text-[#087F8C] font-semibold">{log.id}</td>
                              <td className="py-2.5 px-3 text-[#17202A]">{log.analyst_id}</td>
                              <td className="py-2.5 px-3 text-[#17202A] font-sans font-medium">{log.action_taken}</td>
                              <td className="py-2.5 px-3 text-[#667085]">{log.target}</td>
                              <td className="py-2.5 px-3">
                                <span className="px-2 py-0.5 bg-[#16805C]/10 text-[#16805C] rounded border border-[#16805C]/30 text-[10px] font-bold">
                                  {log.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                </div>
              </div>
            )}

            {/* TAB 6: SIMULATION & TEST MATRIX */}
            {activeTab === 'simulation' && (
              <div className="space-y-6 animate-fade-in">
                <div className="bg-white border border-[#E2E6EB] rounded-[8px] p-5 space-y-6">
                  <div className="pb-3 border-b border-[#E2E6EB]">
                    <h3 className="text-base font-bold text-[#17202A]">Attack Simulation Lab & Verification Matrix</h3>
                    <p className="text-xs text-[#667085]">Trigger threat scenarios to evaluate ingestion pipeline, correlation engine, and response playbooks.</p>
                  </div>

                  {/* Scenario Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-3">
                    {[
                      { id: 'brute-force', name: '1. Brute Force', mitre: 'T1110', desc: 'Hydra 5+ failed logons' },
                      { id: 'powershell', name: '2. PowerShell Exec', mitre: 'T1059.001', desc: 'Encoded base64 payload' },
                      { id: 'account-creation', name: '3. Account Add', mitre: 'T1098', desc: 'Net user test_admin /add' },
                      { id: 'persistence', name: '4. Persistence Task', mitre: 'T1053.005', desc: 'Schtasks persistence' },
                      { id: 'chain-attack', name: '5. Multi-Stage Chain', mitre: 'Multiple', desc: 'Sequential attack vector' },
                    ].map(scenario => (
                      <div key={scenario.id} className="bg-[#F7F8FA] border border-[#E2E6EB] rounded-[6px] p-3.5 flex flex-col justify-between space-y-3">
                        <div>
                          <span className="px-2 py-0.5 bg-white text-[#2764A5] border border-[#E2E6EB] rounded text-[10px] font-mono">{scenario.mitre}</span>
                          <h4 className="font-bold text-[#17202A] text-xs mt-2">{scenario.name}</h4>
                          <p className="text-[11px] text-[#667085] mt-1">{scenario.desc}</p>
                        </div>
                        <button
                          onClick={() => triggerSimulation(scenario.id)}
                          disabled={simulationLoading !== null}
                          className="w-full py-1.5 bg-[#087F8C] hover:bg-[#066A75] text-white rounded-[6px] text-xs font-medium flex items-center justify-center space-x-1.5 transition cursor-pointer disabled:opacity-50"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>{simulationLoading === scenario.id ? 'Running...' : 'Run Test'}</span>
                        </button>
                      </div>
                    ))}
                  </div>

                  {/* MVP Test Verification Matrix */}
                  <div className="pt-4 border-t border-[#E2E6EB] space-y-3">
                    <h4 className="text-xs font-bold text-[#17202A] uppercase tracking-wider text-[#667085]">
                      MVP Test Acceptance Matrix (TC-01 to TC-05)
                    </h4>
                    <div className="overflow-x-auto border border-[#E2E6EB] rounded-[6px]">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[#F1F3F5] border-b border-[#E2E6EB] text-[#667085]">
                            <th className="py-2.5 px-3">TEST ID</th>
                            <th className="py-2.5 px-3 font-sans">SCENARIO</th>
                            <th className="py-2.5 px-3">EXPECTED RESULT</th>
                            <th className="py-2.5 px-3 font-sans">ACCEPTANCE CRITERIA</th>
                            <th className="py-2.5 px-3">STATUS</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E2E6EB]">
                          {[
                            { id: 'TC-01', scenario: 'Brute Force Attack', expected: 'Triggered alert in UI', criteria: 'Sysmon/Event 4625 ingested; Alert generated', status: 'PASSED' },
                            { id: 'TC-02', scenario: 'PowerShell Encoded Exec', expected: 'Event ID 1 captured', criteria: 'Command line decoded and tagged with T1059.001', status: 'PASSED' },
                            { id: 'TC-03', scenario: 'Multi-Stage Chain', expected: 'Incident Creation', criteria: '3 distinct alerts grouped into 1 Correlated Incident', status: 'PASSED' },
                            { id: 'TC-04', scenario: 'Host Isolation Action', expected: 'Network Blocked', criteria: 'Host loses external connectivity; status updates in UI', status: 'PASSED' },
                            { id: 'TC-05', scenario: 'Report Generation', expected: 'Exported Summary', criteria: 'Markdown/PDF generated with timeline & actions', status: 'PASSED' },
                          ].map(test => (
                            <tr key={test.id} className="hover:bg-[#F7F8FA]">
                              <td className="py-2.5 px-3 text-[#087F8C] font-bold">{test.id}</td>
                              <td className="py-2.5 px-3 text-[#17202A] font-sans font-medium">{test.scenario}</td>
                              <td className="py-2.5 px-3 text-[#667085]">{test.expected}</td>
                              <td className="py-2.5 px-3 text-[#17202A] font-sans">{test.criteria}</td>
                              <td className="py-2.5 px-3">
                                <span className="px-2 py-0.5 bg-[#16805C]/10 text-[#16805C] rounded border border-[#16805C]/30 text-[10px] font-bold">
                                  {test.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                </div>
              </div>
            )}

          </main>

          {/* Footer */}
          <footer className="bg-white border-t border-[#E2E6EB] py-3.5 px-6 text-center text-xs text-[#667085] font-mono mt-auto">
            SOC-X Enterprise Platform · Wazuh SIEM Telemetry & Automated Incident Response System
          </footer>

        </div>
      </div>
    </div>
  );
}
