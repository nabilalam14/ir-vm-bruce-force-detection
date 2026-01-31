# 🚨 Brute Force Detection & Incident Response  
## Microsoft Sentinel & Defender for Endpoint  
### Aligned to NIST 800-61 Incident Response Lifecycle

---

## 📌 Incident Overview
This project documents a simulated **brute-force attack investigation** against multiple Azure Virtual Machines using **Microsoft Sentinel** and **Microsoft Defender for Endpoint (MDE)**.

The incident was detected, analyzed, contained, and closed **in accordance with the NIST 800-61 Incident Response Lifecycle**, demonstrating a full end-to-end SOC workflow.

---

# 🧭 NIST 800-61 Incident Response Lifecycle

---

## 1️⃣ Preparation

### Environment & Tooling
- Azure Virtual Machines  
- Microsoft Defender for Endpoint (EDR)  
- Microsoft Sentinel (SIEM)  
- Log Analytics Workspace  
- Kusto Query Language (KQL)  

### Detection Readiness
- Centralized authentication telemetry via `DeviceLogonEvents`
- Sentinel analytics rule configured to detect repeated failed logons
- Entity mappings enabled for:
  - Remote IP
  - Device Name
- Automatic incident creation enabled

**Objective:** Ensure visibility and alerting capability before an attack occurs.

---

## 2️⃣ Detection & Analysis

### Detection Logic
An analytics rule was triggered when:
- The same **remote IP address**
- Failed to authenticate to the same **VM**
- **10+ times within a 5-hour window**

This behavior is consistent with **external brute-force attempts**.

### Failed Logon Detection (KQL)
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount desc
```
<img width="884" height="473" alt="Screenshot 2026-01-31 125550" src="https://github.com/user-attachments/assets/4a35fab2-beef-4f0f-9a1e-47536c4e6ed4" />


### Investigation Findings
- **5 virtual machines** were targeted
- **6 unique public IP addresses** involved
- Activity observed across multiple hosts
- All authentication attempts resulted in **failed logons**

<img width="787" height="594" alt="Screenshot 2026-01-31 131354" src="https://github.com/user-attachments/assets/f76df903-ac74-42e9-9a66-66c601eeb046" />


### Validation: No Successful Authentication
```kql
DeviceLogonEvents
| where RemoteIP in (
  "194.180.49.140",
  "80.94.95.83",
  "201.150.150.54",
  "10.1.0.121",
  "104.248.199.24"
)
| where ActionType != "LogonFailed"
```

**Result:**  
- No successful logons detected  
- No evidence of credential compromise  

---

## 3️⃣ Containment, Eradication, and Recovery

### Containment Actions
- Isolated all affected virtual machines using Microsoft Defender for Endpoint
- Anti-malware scans executed on impacted systems
- Network Security Groups (NSGs) hardened:
  - Blocked public RDP access
  - Allowed access only from a trusted home IP
  - Bastion Host identified as a secure alternative

### Eradication
- No malware or persistence mechanisms detected
- No compromised accounts identified

### Recovery
- Systems returned to normal operation
- Enhanced network restrictions remain in place

---

## 4️⃣ Post-Incident Activity

### Lessons Learned
- Publicly exposed RDP significantly increases attack surface
- Detection was effective, but preventive controls are critical
- NSG hardening should be enforced proactively

### Preventive Recommendations
- Enforce Azure Policy to:
  - Block internet-facing RDP by default
  - Require Bastion Host or private access
- Expand detection rules to include:
  - Successful logon correlation
  - Geo-location anomalies

---

## 5️⃣ Incident Closure

### Final Assessment
- Incident classified as **True Positive**
- Brute-force activity confirmed
- No successful authentication
- No unauthorized access
- Security posture improved post-incident

### MITRE ATT&CK Mapping

| Tactic | Technique |
|------|---------|
| TA0001 – Initial Access | T1110 – Brute Force |
| TA0001 – Initial Access | T1110.001 – Password Guessing |
| TA0006 – Credential Access | T1110 – Brute Force |

---

## 🎯 Skills Demonstrated
- NIST 800-61 Incident Response Lifecycle  
- Microsoft Sentinel (SIEM)  
- Microsoft Defender for Endpoint (EDR)  
- KQL Threat Hunting & Validation  
- Incident Investigation & Containment  
- Azure Network Security (NSGs)  
- MITRE ATT&CK Mapping  
