#!/usr/bin/env python3
"""
SOC L2 Utility Scripts
Automation helpers untuk threat hunting & malware analysis
"""

import requests
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
import os

# =====================================
# IOC Enrichment Functions
# =====================================

class IOCEnricher:
    def __init__(self, vt_api_key, abuse_api_key):
        self.vt_key = vt_api_key
        self.abuse_key = abuse_api_key
        self.db_path = os.path.expanduser('~/soc-workspace/ioc-database.db')
    
    def check_hash_vt(self, file_hash):
        """Check file hash against VirusTotal"""
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'names': data['data']['attributes'].get('names', [])
            }
        return None
    
    def check_ip_abuse(self, ip_address):
        """Check IP against AbuseIPDB"""
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'is_whitelisted': data.get('isWhitelisted', False),
                'usage_type': data.get('usageType', 'Unknown')
            }
        return None
    
    def save_to_db(self, ioc_type, value, source, confidence, description, tags):
        """Save IOC to local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (ioc_type, value, source, confidence, description, tags, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (ioc_type, value, source, confidence, description, tags, datetime.now()))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False
        finally:
            conn.close()
    
    def enrich_hash(self, file_hash):
        """Full enrichment for file hash"""
        print(f"[+] Enriching hash: {file_hash}")
        
        vt_result = self.check_hash_vt(file_hash)
        if vt_result:
            malicious_count = vt_result['malicious']
            
            if malicious_count > 10:
                confidence = 'critical'
            elif malicious_count > 5:
                confidence = 'high'
            elif malicious_count > 0:
                confidence = 'medium'
            else:
                confidence = 'low'
            
            description = f"VT Detection: {malicious_count}/{malicious_count + vt_result['harmless']}"
            self.save_to_db('hash', file_hash, 'VirusTotal', confidence, description, 'malware')
            
            return vt_result
        
        return None
    
    def enrich_ip(self, ip_address):
        """Full enrichment for IP address"""
        print(f"[+] Enriching IP: {ip_address}")
        
        abuse_result = self.check_ip_abuse(ip_address)
        if abuse_result:
            score = abuse_result['abuse_score']
            
            if score > 75:
                confidence = 'critical'
            elif score > 50:
                confidence = 'high'
            elif score > 25:
                confidence = 'medium'
            else:
                confidence = 'low'
            
            description = f"Abuse Score: {score}%, Reports: {abuse_result['total_reports']}, {abuse_result['country']}"
            tags = f"abuse,{abuse_result['usage_type']}"
            
            self.save_to_db('ip', ip_address, 'AbuseIPDB', confidence, description, tags)
            
            return abuse_result
        
        return None


# =====================================
# SIEM Query Helpers
# =====================================

class SIEMQueryHelper:
    
    @staticmethod
    def generate_sentinel_kql(search_type, indicators, timeframe_hours=24):
        """Generate KQL queries for Microsoft Sentinel"""
        
        queries = {
            'failed_logins': f'''
SecurityEvent
| where TimeGenerated > ago({timeframe_hours}h)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, Computer
| where FailedAttempts > 10
| order by FailedAttempts desc
            ''',
            
            'suspicious_powershell': f'''
DeviceProcessEvents
| where TimeGenerated > ago({timeframe_hours}h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", "DownloadString", "EncodedCommand", "bypass", "hidden")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
            ''',
            
            'c2_beaconing': f'''
CommonSecurityLog
| where TimeGenerated > ago({timeframe_hours}h)
| where DeviceAction == "allowed"
| summarize ConnectionCount = count(), AvgBytes = avg(SentBytes + ReceivedBytes) 
    by SourceIP, DestinationIP, DestinationPort, bin(TimeGenerated, 5m)
| where ConnectionCount > 5 and AvgBytes < 1000
| order by SourceIP, TimeGenerated asc
            ''',
            
            'lateral_movement': f'''
SecurityEvent
| where TimeGenerated > ago({timeframe_hours}h)
| where EventID in (4624, 4672)
| where LogonType in (3, 10)
| summarize Systems = make_set(Computer), LogonCount = count() by Account
| where LogonCount > 5
| order by LogonCount desc
            ''',
            
            'ioc_hunt': f'''
let IOCs = dynamic([{", ".join([f'"{ioc}"' for ioc in indicators])}]);
union
    (DeviceNetworkEvents | where RemoteIP in (IOCs) or RemoteUrl in (IOCs)),
    (DnsEvents | where Name in (IOCs)),
    (DeviceFileEvents | where SHA256 in (IOCs) or MD5 in (IOCs))
| where TimeGenerated > ago({timeframe_hours}h)
| project TimeGenerated, DeviceName, ActionType, IOC = coalesce(RemoteIP, RemoteUrl, Name, SHA256, MD5)
            '''
        }
        
        return queries.get(search_type, "# Query type not found")
    
    @staticmethod
    def generate_qradar_aql(search_type, timeframe_minutes=1440):
        """Generate AQL queries for QRadar"""
        
        queries = {
            'top_offenses': f'''
SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm') as "Start Time",
       offense_id as "Offense ID",
       magnitude as "Magnitude",
       offense_type as "Type",
       description as "Description"
FROM events
WHERE starttime > LAST {timeframe_minutes} MINUTES
ORDER BY magnitude DESC
LIMIT 20
            ''',
            
            'suspicious_dns': f'''
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm') as "Time",
       sourceip as "Source IP",
       destinationip as "DNS Server",
       "Domain Name" as qname,
       COUNT(*) as "Query Count"
FROM events
WHERE qid IN (SELECT qid FROM qidmap WHERE logsourcetypename = 'DNS')
  AND devicetime > LAST {timeframe_minutes} MINUTES
  AND (qname LIKE '%.tk' OR qname LIKE '%.ml' OR qname LIKE '%.ga' 
       OR LENGTH(qname) > 50
       OR REGEXPMATCH(qname, '[0-9]{{8,}}'))
GROUP BY sourceip, destinationip, qname
HAVING COUNT(*) > 5
ORDER BY "Query Count" DESC
            ''',
            
            'data_exfiltration': f'''
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm') as "Time",
       sourceip as "Source",
       destinationip as "Destination",
       SUM(destinationbytes) as "Total Bytes Out"
FROM events
WHERE devicetime > LAST {timeframe_minutes} MINUTES
  AND destinationport NOT IN (80, 443, 53, 22, 3389)
GROUP BY sourceip, destinationip
HAVING SUM(destinationbytes) > 100000000
ORDER BY "Total Bytes Out" DESC
            '''
        }
        
        return queries.get(search_type, "-- Query type not found")


# =====================================
# Incident Documentation
# =====================================

class IncidentReporter:
    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.expanduser('~/soc-workspace/ioc-database.db')
    
    def create_incident(self, incident_id, severity, summary):
        """Create new incident in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO incidents (incident_id, severity, status, summary)
                VALUES (?, ?, 'Open', ?)
            ''', (incident_id, severity, summary))
            
            conn.commit()
            print(f"[+] Incident {incident_id} created successfully")
            return True
        except Exception as e:
            print(f"[-] Error creating incident: {e}")
            return False
        finally:
            conn.close()
    
    def generate_report_template(self, incident_id, title):
        """Generate incident report template"""
        template = f"""
# INCIDENT REPORT

**Incident ID:** {incident_id}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Severity:** [Critical/High/Medium/Low]
**Status:** Investigation

---

## Executive Summary
{title}

---

## Timeline of Events

| Time (UTC) | Event | Source |
|------------|-------|--------|
| YYYY-MM-DD HH:MM | Initial detection | [SIEM/EDR/etc] |
| | | |

---

## Technical Details

### Initial Detection
- **Alert Source:** 
- **Alert Name:** 
- **Triggered Rule/Signature:** 

### Affected Systems
- **Hostname:** 
- **IP Address:** 
- **Operating System:** 
- **User Account:** 

### Indicators of Compromise (IOCs)

#### File Hashes
```
MD5: 
SHA1: 
SHA256: 
```

#### Network Indicators
```
IP Addresses: 
Domains: 
URLs: 
```

#### Registry Keys / File Paths
```
```

---

## Investigation Steps

1. **Initial Triage**
   - [ ] Isolate affected systems
   - [ ] Preserve evidence
   - [ ] Identify scope

2. **Analysis**
   - [ ] Log analysis (SIEM)
   - [ ] Network traffic analysis
   - [ ] Endpoint forensics
   - [ ] Memory analysis (if applicable)

3. **Containment**
   - [ ] Block malicious IPs/domains
   - [ ] Disable compromised accounts
   - [ ] Apply security patches

4. **Eradication**
   - [ ] Remove malware
   - [ ] Close attack vectors
   - [ ] Reset credentials

5. **Recovery**
   - [ ] Restore from clean backups
   - [ ] Verify system integrity
   - [ ] Monitor for reinfection

---

## Root Cause Analysis

**Attack Vector:** 

**Exploited Vulnerability:** 

**Security Control Gaps:** 

---

## Impact Assessment

**Confidentiality:** [None/Low/Medium/High]
**Integrity:** [None/Low/Medium/High]
**Availability:** [None/Low/Medium/High]

**Estimated Impact:** 

---

## Remediation Actions

### Immediate Actions Taken
1. 
2. 
3. 

### Long-term Recommendations
1. 
2. 
3. 

---

## Lessons Learned

**What Went Well:**
- 

**What Could Be Improved:**
- 

**Action Items:**
- [ ] 
- [ ] 

---

## References
- MITRE ATT&CK Techniques: 
- Threat Intelligence: 
- Related Incidents: 

---

**Prepared By:** [Your Name]
**Reviewed By:** 
**Approved By:** 
"""
        
        # Save to file
        report_path = os.path.expanduser(f'~/incident-reports/{incident_id}_report.md')
        with open(report_path, 'w') as f:
            f.write(template)
        
        print(f"[+] Report template created: {report_path}")
        return report_path


# =====================================
# Malware Analysis Helpers
# =====================================

class MalwareAnalyzer:
    
    @staticmethod
    def calculate_hashes(file_path):
        """Calculate MD5, SHA1, SHA256 for a file"""
        if not os.path.exists(file_path):
            return None
        
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    @staticmethod
    def extract_strings(file_path, min_length=4):
        """Extract printable strings from file"""
        if not os.path.exists(file_path):
            return []
        
        strings = []
        with open(file_path, 'rb') as f:
            current_string = b''
            while byte := f.read(1):
                if 32 <= byte[0] <= 126:  # Printable ASCII
                    current_string += byte
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('ascii', errors='ignore'))
                    current_string = b''
        
        return strings
    
    @staticmethod
    def generate_yara_template(sample_name, suspicious_strings):
        """Generate YARA rule template"""
        rule = f'''
rule Detect_{sample_name.replace(" ", "_")}
{{
    meta:
        description = "Detects {sample_name}"
        author = "SOC Team"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash = ""
        
    strings:
'''
        
        for i, s in enumerate(suspicious_strings[:10], 1):
            if len(s) > 3:
                rule += f'        $s{i} = "{s}" wide ascii\n'
        
        rule += '''
    condition:
        3 of them
}
'''
        return rule


# =====================================
# Example Usage
# =====================================

if __name__ == "__main__":
    print("SOC L2 Utility Scripts Loaded")
    print("\nAvailable Classes:")
    print("  - IOCEnricher: Enrich IOCs with threat intelligence")
    print("  - SIEMQueryHelper: Generate SIEM queries")
    print("  - IncidentReporter: Document incidents")
    print("  - MalwareAnalyzer: Analyze malware samples")
    print("\nExample usage:")
    print("  enricher = IOCEnricher(vt_key='YOUR_KEY', abuse_key='YOUR_KEY')")
    print("  enricher.enrich_hash('44d88612fea8a8f36de82e1278abb02f')")
    print("\n  reporter = IncidentReporter()")
    print("  reporter.create_incident('INC-2024-001', 'High', 'Ransomware detected')")
