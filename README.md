
# 🕵️‍♂️ Threat Hunt Report: **EchoLeak - AI Assisted Exfiltration**

**Analyst:** Alton Stewart  
**Date Completed:** October 18, 2026   
**Environment Investigated:** Financial advisory firm that utilizes M365 E5 licenses with Co-Pilot. An analytics rule flags unusual file access, where sensitive files were accessed in an extremely brief period of time. The connected user states they were just asking Co-Pilot to summarize a report.   
**Timeframe:** `September 20, 2025 – 9:00:00 to 11:00:00 (UTC)`    
**Duration:** 2 hours  
**Severity:** High

---

## 🧠 Scenario Overview
Cormorant Capital Partners, a mid-size financial advisory firm with approximately 200 employees using M365 E5 with Copilot for Microsoft 365, is investigating a critical data security anomaly. At 10:42 UTC on 20 September 2026, an analytics rule flagged an unusual file access burst where financial analyst Emily Chen accessed five highly sensitive documents—including board meeting notes, M&A target assessments, and salary reviews—within a six-second window. While Chen stated she only asked Copilot to summarize a routine quarterly market review email received ninety minutes prior, investigation logs show zero unusual sign-in or user activity during that gap, raising urgent questions regarding why the AI assistant accessed unrelated, privileged data and whether any information has been exfiltrated from the organization.

**Add this to end**
This incident reproduces the CVE-2025-32711 vulnerability cluster documented by Aim Security and Unit 42 (Palo Alto Networks), which centers on indirect prompt injection. In this scenario, malicious instructions embedded within the external email's attachment successfully hijacked M365 Copilot during the summarization process. By exploiting the assistant's legitimate Microsoft Graph API capabilities, the injection forced Copilot to search for, access, and potentially exfiltrate sensitive data without the user's explicit knowledge or intent, serving as a primary case study for students analyzing LLM-based security risks.


What is known at handoff

External email with attachment received by emily.chen at approximately 09:15 UTC
Anomalous file access by emily.chen at 10:42, five files never previously opened
Copilot invocation shortly before the file access burst
No sign-in anomalies in Entra ID for emily.chen during the window

---

## 🎯 Executive Summary
##REDO
The adversary gained access via brute-forced RDP credentials (`slflare`), executed `msupdate.exe`, and persisted with a scheduled task (`MicrosoftUpdateSync`). They disabled Windows Defender scanning, ran reconnaissance (`systeminfo`), staged sensitive data into `backup_sync.zip`, and attempted to exfiltrate it via `curl` to `185.92.220.87:8081`. Multiple outbound connections (PowerShell, msupdate.exe, curl) to `185.92.220.87` indicate C2 activity. The attacker’s intent was **data theft**, with exfiltration staged from the SLFlare user profile.

---

## ✅ Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **1** | Initial Access - Sender's Address | `quarterly.reports@globalfinancereview.net` |
| **2** | Initial Access - Poisoned document | `Q3-2026-Global-Markets-Review.docx` |
| **3** | Initial Access - Time gap | `1hr27mins` |
| **4** | Execution - User Prompt | `Summarise the key findings of this quarterly report` |
| **5** | Execution - Anomalous tool calls Task Created | `Graph.SearchFiles, site:cormorantcapital.sharepoint.com` |
| **6** | Execution - ATLAS technique | `T0051` |
| **7** | Collection - Sensitive file count | `5` |
| **8** | Collection - Exfiltration domain | `metrics-cdn.analyticshub.io` |
| **9** | Collection - Exfiltration mechanism | `indirect prompt injection attack, markdown-embedded tracking pixels` |
| **10** | Exfiltration - Accessed files | `Copilot System Configuration - Cormorant.json, Client Portfolio - Henderson Family Office.xlsx, Salary Review FY2027 - Executive Summary.pdf, Project Falcon - M&A Target Assessment.xlsx, Board Meeting Minutes - October 2026.docx` |
| **11** | Exfiltration - Data content visibility | `No, The specific limitation is that the audit trail captures metadata and structural transaction records rather than the full inner payload or file text of the accessed documents.` |
| **12** | Exfiltration - System prompt exposure | `Copilot system configuration, matters because that information can be used to craft future attacks.` |
| **13** | Judgement - Copilot behavior: normal or hijacked | `Claim does not hold, as the telemetry shows an impossible human processing velocity from 10:42:41 until 10:42:55, thus proving there was a scripted payload embedded inside the document the user opened.` |
| **14** | Judgement - Access pattern analysis | `Differences between user intent and copilot actions, the fast velocity of copilot responses, the external URLs hidden in image links to exfiltrate data.` |
| **15** | Incident Response - SearchLeak scope | `4 additional files, confidential, restricted, board, acquisition, salary` |
| **16** | Incident Response - Total file count. | `13` |
| **17** | Incident Response - Incident classification | `I'd classify this incident as an External Input Manipulation, not a compromised user account or a compromised Co-Pilot configuration` |

---

## Flag by Flag

### 🚩 Flag 1 – Sender's Address
**MITRE Technique:** T1566.001 - Phishing: Spearphishing Attachment  

The query inspects email messages the user received, in order to isolate the specific email that delivered the malicious attachment. 

**Question:** Which external email address delivered the document that preceded the anomalous file access.  
**Finding:** `quarterly.reports@globalfinancereview.net`     
**KQL Query Used:**
````kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T10:00:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "MessageReceived" and OfficeWorkload == "Exchange"
| project TimeGenerated, SenderAddress, Subject, AttachmentNames

````
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 2 – Poisioned document
**MITRE Technique:** T1566.001 - Phishing: Spearphishing Attachment 

The same office activitty telemetry shows the name of the malicious attachment.

**Question:** What is the name of the document that was attached to the delivery email?     
**Finding:** `Q3-2026-Global-Markets-Review.docx`   
**KQL Query Used:** (same as Flag 1)  

<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 3 – Time gap
**MITRE Techniques:** T1204.002 - User Execution: Malicious File\

Email message delivered at `09:15:22`, and the document was first accessed at `10:42:08`. Gap of `1hr 27mins`. Not quite zero-click, as the user must open the document and invoke Co-Pilot in order to trigger the malicious payload. The attack chain depends on the user invoking Co-Pilot.

**Question:** How much time elapsed between the email delivery and Emily's first interaction with the document? What does this gap tell you about the attack model?    
**Finding:** `1hr 27mins`   
**KQL Query Used:**
````kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where (Operation == "MessageReceived" and SenderAddress has "globalfinancereview")
    or (Operation == "FileAccessed" and OfficeObjectId has "Q3-2026")
| project TimeGenerated, Operation, OfficeObjectId, SenderAddress, Subject
| order by TimeGenerated asc
````
imag of FLAG #3
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 4 – User Prompt
**MITRE Technique:** T1059 - Command and Scripting Interpreter

(ADD QUICK SUMMARY OF QUERY)
The query extracts the full command line parameters tied to the malicious binary execution. This reveals the attacker’s intent to bypass execution policy and run a PowerShell script.

**Question:** `What did Emily ask Copilot to do with the document?`  
**Finding:** `Summarise the key findings of this quarterly report`    
**KQL Query Used:** 
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:43:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Prompt"
| project TimeGenerated, UserPrompt, Application
````
imag of FLAG #4
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 5 – Anomalous tool calls Task Created
**MITRE Technique:** T1213 - Data from Information Repositories

(ADD BRIEF SUMMARY OF QUERY)
Registry event data is searched for TaskCache entries to detect persistence mechanisms. This highlights the attacker’s creation of the MicrosoftUpdateSync scheduled task.

**Question:** `After Emily's prompt, what tool calls did Copilot make that go beyond what a document summarisation requires? Name the tools and their targets.`  
**Finding:** `Graph.SearchFiles, site:cormorantcapital.sharepoint.com`   
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:30Z) .. datetime(2026-09-20T10:43:30Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "ToolCall"
| project TimeGenerated, ToolName, ToolParameters, DataSourcesAccessed
````

image of FLAG #5
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 6 – ATLAS technique
**MITRE Technique:** AML.T0051.001 - LLM Prompt Injection: Indirect

(ADD BRIEF SUMMARY OF QUERY)
Registry modifications are reviewed to detect Defender configuration changes. This shows the adversary weakening defenses by excluding C:\Windows\Temp from scanning.

**Question:** `Which ATLAS technique describes the method the attacker used to make Copilot follow instructions hidden in the document?`  
**Finding:** `T0051`  
**KQL Query Used:**

No KQL query needed. This is a knowledge flag referencing the ATLAS taxonomy.

---

### 🚩 Flag 7 – Sensitive file count
**MITRE Technique:** T1213 - Data from Information Repositories 

(ADD BRIEF SUMMARY OF QUERY)
Process events are filtered for cmd.exe with the systeminfo argument. This identifies the attacker’s reconnaissance activity to learn system details.

**Question:** `How many sensitive files did Copilot access that Emily had never opened before?`    
**Finding:** `5`      
**KQL Query Used:**
````kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:43:15Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where OfficeObjectId !has "Q3-2026"
| summarize dcount(OfficeObjectId)
````
image of FLAG #7
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 8 – Exfiltration domain
**MITRE Technique:** T1041 - Exfiltration Over C2 Channel

File creation logs are queried to spot sensitive data being staged. This captures the creation of backup_sync.zip as a precursor to exfiltration.

**Question:** `Through what domain was the extracted data exfiltrated? Where in the telemetry does it appear?`    
**Finding:** `metrics-cdn.analyticshub.io`     
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:30Z) .. datetime(2026-09-20T10:44:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where CopilotResponse has "metrics-cdn" or CopilotResponse has "analyticshub"
| project TimeGenerated, CopilotResponse
````

image of FLAG #7
<img width="1000" height="800" alt="Deploying VM" src="Threat Hunt Images/Flag1.png"/> 

---

### 🚩 Flag 9 – Exfiltration mechanism
**MITRE Technique:** T1041 - Exfiltration Over C2 Channel 

Network events are inspected for outbound connections to known malicious IPs. This confirms contact with external C2 infrastructure at 185.92.220.87.

**Question:** `Describe the technical mechanism Copilot used to send the data out. How does it bypass endpoint network monitoring?`    
**Finding:** `indirect prompt injection attack, markdown-embedded tracking pixels`    
**KQL Query Used:**
````kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-16) .. datetime(2025-09-19))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by Timestamp asc
````

![Flag 1](Images/flag9.png)

---

### 🚩 Flag 10 – Exfiltration Attempt
**MITRE Technique:** T1048.003 – Exfiltration Over Unencrypted Protocol  

The query isolates curl.exe network activity on port 8081. This directly exposes the attacker’s attempt to exfiltrate the staged archive to their server.

**Question:** `How many sensitive files did Copilot access that Emily had never opened before?`    
**Finding:** `5`     
**KQL Query Used:**
````kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where RemoteIP == "185.92.220.87"
| where Timestamp between (datetime(2025-09-16) .. datetime(2025-09-19))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by Timestamp desc 
````
![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 11 – Exfiltration Attempt
**MITRE Technique:** T1048.003 – Exfiltration Over Unencrypted Protocol  

The query isolates curl.exe network activity on port 8081. This directly exposes the attacker’s attempt to exfiltrate the staged archive to their server.

**Question:** `How many sensitive files did Copilot access that Emily had never opened before?`    
**Finding:** `5`    
**KQL Query Used:**
````kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where RemoteIP == "185.92.220.87"
| where Timestamp between (datetime(2025-09-16) .. datetime(2025-09-19))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by Timestamp desc 
````
![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 12 – Exfiltration Attempt
**MITRE Technique:** T1048.003 – Exfiltration Over Unencrypted Protocol  

The query isolates curl.exe network activity on port 8081. This directly exposes the attacker’s attempt to exfiltrate the staged archive to their server.

**Question:** `How many sensitive files did Copilot access that Emily had never opened before?`    
**Finding:** `5`     
**KQL Query Used:**
````kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where RemoteIP == "185.92.220.87"
| where Timestamp between (datetime(2025-09-16) .. datetime(2025-09-19))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType
| order by Timestamp desc 
````
![Flag 1](Images/flag9_and_10.png)

---

## 📅 Timeline of Events

| Timestamp (UTC) | Event | Details |
|-----------------|-------|---------|
| 2025-09-16 11:43:46 | Initial RDP login success | Attacker IP: `159.26.106.84` |
| 2025-09-16 11:45:12 | Binary executed | `msupdate.exe` |
| 2025-09-16 11:46:00 | Scheduled Task created | `MicrosoftUpdateSync` |
| 2025-09-16 11:47:30 | Defender exclusions modified | Excluded path `C:\Windows\Temp` |
| 2025-09-16 11:48:22 | Discovery executed | `cmd.exe /c systeminfo` |
| 2025-09-16 12:10:45 | Archive created | `backup_sync.zip` |
| 2025-09-16 12:20:30 | Outbound C2 traffic | Destination `185.92.220.87` |
| 2025-09-16 12:43:42 | Exfiltration attempt | `curl.exe` POST `backup_sync.zip` → `185.92.220.87:8081` |

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Brute Force | T1110.001 |
| Credential Access | Valid Accounts | T1078 |
| Execution | Command & Script Interpreter (Windows) | T1059.003 |
| Execution | User Execution | T1204.002 |
| Persistence | Scheduled Task | T1053.005 |
| Defense Evasion | Impair Defenses | T1562.001 |
| Discovery | System Information Discovery | T1082 |
| Collection | Local Data Staging | T1074.001 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Exfiltration | Exfiltration Over Unencrypted Protocol | T1048.003 |

---

## 🔷 Diamond Model Summary

- **Adversary:** External attacker using brute-force RDP from `159.26.106.84`  
- **Infrastructure:** Remote IP `185.92.220.87`, port `8081` for exfiltration  
- **Capabilities:** Credential access, persistence via scheduled tasks, defense evasion, discovery, exfiltration  
- **Victim:** Windows host `slflarewinsysmo`, user account `slflare`  

---

## 📌 Lessons Learned
- External RDP access remains a high-risk entry vector.  
- Lack of MFA allowed brute-force compromise.  
- Data staging in `AppData\Local\Temp` indicates poor endpoint monitoring coverage.  
- Outbound traffic controls insufficient to block malicious curl exfiltration.  

---

## 🛠 Recommendations

### Immediate Actions Needed
1. Disable RDP exposure to the internet or enforce VPN-only access.  
2. Force password reset for `slflare` and all privileged accounts.  
3. Block outbound connections to `185.92.220.87` and monitor for related IOCs.  

### Short-term Improvements (1–30 days)
1. Enforce MFA for all remote access accounts.  
2. Harden scheduled task creation monitoring with alerting.  
3. Audit and reset Windows Defender exclusions across endpoints.  

### Long-term Security Enhancements
1. Implement network segmentation to isolate user workstations from sensitive resources.  
2. Deploy DLP (Data Loss Prevention) and outbound proxy controls.  
3. Regularly conduct red team simulations of RDP brute force and exfiltration.  

### Detection Improvements (Optional)
- **Monitoring Gaps Identified:** Lack of visibility on archive creation and Defender exclusion.  
- **Recommended Alerts:** New scheduled tasks, Defender exclusions, abnormal curl usage.  
- **Query Improvements:** Expand hunting queries to baseline and flag abnormal `cmd.exe` + `systeminfo` usage.  
