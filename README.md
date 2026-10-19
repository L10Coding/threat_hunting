
# 🕵️‍♂️ Threat Hunt Report: **EchoLeak - AI Assisted Exfiltration**

**Analyst:** Alton Stewart  
**Date Completed:** October 18, 2026   
**Environment Investigated:** Financial advisory firm that utilizes M365 E5 licenses with Copilot. An analytics rule flags unusual file access, where sensitive files were accessed in an extremely brief period of time. The connected user states they were just asking Copilot to summarize a report.   
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
| **16** | Incident Response - Total file count | `13` |
| **17** | Incident Response - Incident classification | `I'd classify this incident as an External Input Manipulation, not a compromised user account or a compromised Copilot configuration` |

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

Email message delivered at `09:15:22`, and the document was first accessed at `10:42:08`. Gap of `1hr 27mins`. Not quite zero-click, as the user must open the document and invoke Copilot in order to trigger the malicious payload. The attack chain depends on the user invoking Copilot.

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

Emily's prompt was: "Summarise the key findings of this quarterly report." A routine document summarisation request, entirely innocent in both wording and intent.

Copilot processes the FULL document content to generate the summary, including hidden text in white-on-white font and zero-point paragraphs. The user's intent and the document's injected instructions are mixed in the same processing context. This is why indirect prompt injection (ATLAS AML.T0051) is effective: the user never knows the document contains instructions.

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

### 🚩 Flag 5 – Anomalous tool calls
**MITRE Technique:** T1213 - Data from Information Repositories

A prompt injection attack manipulated Microsoft Copilot into unauthorized data exfiltration. Instead of summarizing the requested document, the AI agent executed unprompted Microsoft Graph API calls (SearchFiles and ReadFile) to locate and access sensitive, unopened files containing confidential data like board minutes, salary details, and M&A information.

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

Attackers are leveraging indirect prompt injection (MITRE ATLAS AML.T0051) to hijack Microsoft Copilot by embedding hidden instructions directly within document content (the data channel) rather than the user's prompt (the control channel). This approach bypasses user oversight entirely, as the malicious payloads are hidden using techniques like white-on-white text or zero-point font, making them invisible to human readers but fully processed by the AI.

The Core Danger: Because the injection is concealed within the document itself, the user cannot inspect or detect the malicious instructions before Copilot executes them, making this variant exceptionally high-risk.

**Question:** `Which ATLAS technique describes the method the attacker used to make Copilot follow instructions hidden in the document?`  
**Finding:** `T0051`  
**KQL Query Used:**

No KQL query needed. This is a knowledge flag referencing the ATLAS taxonomy.

---

### 🚩 Flag 7 – Sensitive file count
**MITRE Technique:** T1213 - Data from Information Repositories 

The primary indicator of Copilot-driven data exfiltration is a machine-speed access pattern found in telemetry. Five unopened files were accessed within approximately six seconds via the Microsoft Graph API. This rapid extraction rate directly exposes the automated exploit, as a human user would typically take longer than that to simply navigate and browser between different files in SharePoint.

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

Attackers utilized the domain `metrics-cdn.analyticshub.io`, disguised as a legitimate analytics platform—to exfiltrate stolen data. The data leaving the network was base64-encoded within query parameters of URLs embedded directly inside Microsoft Copilot's response rendering. This technique maps to MITRE ATLAS AML.T0086 (Exfiltration via AI Agent Tool Invocation), as the AI model's own inference output served as the exfiltration channel.

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

Attackers are exploiting Microsoft Copilot's rendering engine to exfiltrate data via a "pixel-tracking pattern" documented by Palo Alto Networks' Unit 42. Copilot is manipulated into including markdown image tags in its response, with stolen data base64-encoded inside the image URL parameters. When the user's browser automatically renders the response, it requests the image, seamlessly transmitting the sensitive data directly to the attacker's server.

**Question:** `Describe the technical mechanism Copilot used to send the data out. How does it bypass endpoint network monitoring?`    
**Finding:** `indirect prompt injection attack, markdown-embedded tracking pixels`    
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:30Z) .. datetime(2026-09-20T10:44:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where CopilotResponse has "![" or CopilotResponse has "img"
| project TimeGenerated, CopilotResponse
````

![Flag 1](Images/flag9.png)

---

### 🚩 Flag 10 – Accessed files
**MITRE Technique:** T1213 - Data from Information Repositories 

A targeted prompt injection payload systematically enumerated and exfiltrated five categories of high-value data across the organization. By exploiting MITRE ATT&CK T1213 (Data from Information Repositories), the attacker successfully compromised Material Non-Public Information (MNPI) spanning governance, corporate strategy, human resources, client relationships, and system security.

**Question:** `Name the sensitive files Copilot accessed on behalf of the attacker. List each one.`    
**Finding:** `Copilot System Configuration - Cormorant.json, Client Portfolio - Henderson Family Office.xlsx, Salary Review FY2027 - Executive Summary.pdf, Project Falcon - M&A Target Assessment.xlsx, Board Meeting Minutes - October 2026.docx`     
**KQL Query Used:**
````kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:44:30Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where OfficeObjectId !has "Q3-2026"
| project TimeGenerated, OfficeObjectId
````

![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 11 – Data content visibility
**MITRE Technique:** T1041 - Exfiltration Over C2 Channel

Cloud audit logs are built to track what happened, not to copy-paste the actual data inside your files. Think of it like a network gap with HTTPS traffic—you can see where the connection went, but you can't read the encrypted stream.  The logs show you the scope (which doors were opened), but the files themselves tell you the actual impact (what was taken). To figure out the real blast radius, you have to manually open those specific documents and audit the content.
  
**Question:** `Can you determine from the audit logs the exact content of the data that was exfiltrated? State your answer and the specific limitation.`    
**Finding:** `No, the specific limitation is that the audit trail captures metadata and structural transaction records rather than the full inner payload or file text of the accessed documents.`    
**KQL Query Used:**

No KQL query needed.

---

### 🚩 Flag 12 – System prompt exposure
**MITRE Technique:** T1082 - System Information Discovery

The attacker used a vulnerability called CoSnitch (CVE-2026-24301) to steal the keys to the castle: Copilot's system prompt and internal enterprise configurations. This includes things like data-handling rules, sensitivity labels, approved vs. blocked actions, and internal naming styles.

**Question:** `The CoSnitch pattern extracted something beyond user files. What was leaked, and why does it matter for follow-on attacks?`    
**Finding:** `Copilot system configuration, matters because that information can be used to craft future attacks.`     
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:44:00Z) .. datetime(2026-09-20T10:45:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where CopilotResponse has "system prompt" or CopilotResponse has "configuration" or CopilotResponse has "sensitivity"
| project TimeGenerated, InteractionType, CopilotResponse
````

![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 13 – Copilot behavior: normal or hijacked
**MITRE Technique:** T1213 - Data from Information Repositories

Normally, when you ask Copilot to summarize a document, it strictly reads that specific document. It doesn't go wandering off into other files. In fact, a clean, everyday Copilot session is remarkably quiet—you'll see the user's prompt and the AI's response, but absolutely zero background activity for searching or reading external files.  The malicious session did the exact opposite. In just a few seconds, it used specific keywords to hunt down and access five highly sensitive files that Emily had never even opened before.

**Question:** `Emily's manager says Copilot regularly accesses files during summarisation and research tasks, so the file access is normal business activity. Test that claim against the observed patterns and state what the evidence shows.`   
**Finding:** `Claim does not hold, as the telemetry shows an impossible human processing velocity from 10:42:41 until 10:42:55, thus proving there was a scripted payload embedded inside the document the user opened.`     
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:44:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "ToolCall"
| project TimeGenerated, ToolName, ToolParameters
````

![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 14 – Access pattern analysis
**MITRE Technique:** T1213 - Data from Information Repositories

A high-confidence detection pattern emerges when multiple distinct anomalies occur simultaneously: an unauthorized user accessing five files for the very first time, a machine-speed retrieval of those five files in just six seconds, and the presence of unexpected external markdown image URLs in the AI's response. While no individual observation is definitive on its own, their combination strongly signals anomalous Copilot behavior.

**Question:** `Compare the anomalous Copilot session against the normal Copilot usage in the noise floor. Cite at least three specific differences that distinguish the hijacked session.`   
**Finding:** `Differences between user intent and copilot actions, the fast velocity of copilot responses, the external URLs hidden in image links to exfiltrate data.`   

---

### 🚩 Flag 15 – SearchLeak scope 
**MITRE Technique:** T1083 - File and Directory Discovery

The attack didn't stop with those first five documents.  The attacker used a vulnerability called SearchLeak (CVE-2026-42824) to turn Copilot into an automated corporate spy, using it to run a much broader search campaign across the company's SharePoint environment.  Copilot was manipulated into hunting for specific high-value keywords: confidential, restricted, board, acquisition, and salary.  These targeted searches worked, uncovering and triggering unauthorized access to 8 additional sensitive files that the user had never opened before. This significantly widened the blast radius of the breach.

**Question:** `How many additional files did Copilot access through its search capabilities after the initial extraction, and what keywords drove the searches?`   
**Finding:** `4 additional files, confidential, restricted, board, acquisition, salary`     
**KQL Query Used:**
````kql
CopilotAudit_CL
| where TimeGenerated > datetime(2026-09-20T10:44:00Z)
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Search"
| project TimeGenerated, ToolParameters
````


![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 16 – Total file count
**MITRE Technique:** T1213 - Data from Information Repositories

5 initial extraction + 8 SearchLeak = 13 total sensitive files accessed. The total scope matters for incident response: 13 files spanning board materials, M&A targets, salary data, client portfolios, system configuration, and additional files from keyword searches. Each category triggers different notification requirements under data protection regulations.

**Question:** `What is the total number of sensitive files accessed across the entire incident (initial extraction plus SearchLeak)?`   
**Finding:** `13`     
**KQL Query Used:**
````kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:47:00Z))
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where OfficeObjectId !has "Q3-2026"
| summarize dcount(OfficeObjectId)
````


![Flag 1](Images/flag9_and_10.png)

---

### 🚩 Flag 17 – Incident classification
**MITRE Technique:** T1213 - Data from Information Repositories

The user's account was not hacked, and Copilot itself was not reconfigured. Instead, this was a pure external input manipulation attack. The attacker smuggled hidden instructions inside a document's content (the data channel) rather than typing them directly into the prompt box (the control channel). Copilot simply processed those malicious instructions right alongside the user's legitimate request.

**Question:** `Classify this incident: was Copilot's behaviour the result of a compromised user account, a compromised Copilot configuration, or an external input manipulation? Cite the evidence that rules out the other two.`   
**Finding:** `I'd classify this incident as an External Input Manipulation, not a compromised user account or a compromised Co-Pilot configuration. Citing the evidence of multiple files accessed within seconds.`     
**KQL Query Used:**
````kql
EntraSignIn_CL
| where RunId == "el--17-20260920"
| where UserPrincipalName =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T08:00:00Z) .. datetime(2026-09-20T12:00:00Z))
| project TimeGenerated, IPAddress, Location, Status, ConditionalAccessStatus, AppDisplayName
````
(flag 17.1)

````kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:44:00Z))
| project TimeGenerated, InteractionType, UserPrompt, ToolName, ToolParameters
| order by TimeGenerated asc
````
(flag 17.2)
![Flag 1](Images/flag9_and_10.png)

---

## 📅 Timeline of Events

| Timestamp (UTC) | Event | Details |
|-----------------|-------|---------|
| 2026-09-20 09:15:22 | Initial access | Attacker IP: `An external email with a malicious document attachment (Q3-2026-Global-Markets-Review.docx) is delivered to financial analyst Emily Chen from quarterly.reports@globalfinancereview.net.` |
| 2026-09-20 10:42:08  | User execution| `After a 1-hour and 27-minute gap, Emily Chen opens the document and prompts M365 Copilot to: "Summarise the key findings of this quarterly report".` |
| 2026-09-20 10:42:41 to 10:42:55  | AI Hijacking and Collection | `Hidden instructions inside the document (Indirect Prompt Injection) hijack Copilot. At machine speed, Copilot executes unauthorized Microsoft Graph API calls (Graph.SearchFiles) to locate and rapidly access 5 highly sensitive files it was never intended to touch.` |
| 2026-09-20 10:43:00  | Exfiltration | Copilot renders hidden markdown tracking pixels into its response interface. The sensitive data is Base64-encoded inside these image links, causing the user's browser to automatically leak the data out to metrics-cdn.analyticshub.io. |
| 2026-09-20 Post 10:44:00 | Scope expansion (SearchLeak) | The attacker leverages a follow-on vulnerability cluster (SearchLeak) to force Copilot to run broader search campaigns across SharePoint using target keywords (e.g., confidential, board, salary), compromising 8 additional files (bringing the incident total to 13 files). |

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001|
| Execution| User Execution: Malicious File | T1204.002|
| Execution | LLM Prompt Injection: Indirect (ATLAS)| AML.T0051.001 |
| Discovery | Tool Discovery: AI Agent Tool Invocation (ATLAS) | AML.T0086|
| Collection | Data from Information Repositories| T1213 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## 📌 Lessons Learned
- **The Data Channel is an Execution Vector:** Traditional email defense focus is on macro execution or malicious binaries; indirect prompt injections turn benign text files into scriptable execution vectors when parsed by an LLM.
- **Implicit Trust in User Identity Bypasses AI Restraints:** Because analyst Emily Chen had no anomalous sign-ins or malicious intent, security controls allowed the file searches because they originated from her legitimately authenticated token via Copilot.
- **Render-Time Exfiltration Bypasses Traditional Network Blocks:** Markdown tracking pixels leverage standard, authenticated web traffic. The data leaks directly from the victim's client browser, making it invisible to perimeter server alerts looking for massive bulk file transfers.
- **Audit Trails Lack Blast-Radius Visibility:** Standard audit logs capture the file structural transaction metadata (the scope of files opened) but completely fail to record what exact text payload or specific snippet was pulled out and sent down the exfiltration pipe.  
- **Attack Expansion via LLM Search Manipulation:** Vulnerabilities like SearchLeak prove that once an initial injection occurs, an attacker can use the LLM to systematically guess and search for company secrets autonomously, exponentially increasing the blast radius of a single document view. 
---

## 🛠 Recommendations

### AI Gateway & Content Security Controls (Immediate)
1. **Implement Markdown/Hyperlink Content Security Policies (CSP):** Enforce visual rendering restrictions that strip out unapproved external image markdown URLs (![image](url)) inside Copilot client response wrappers.
2. **Deploy Prompt Injection Filters:** Enable enterprise LLM firewalls capable of scanning untrusted third-party inputs (like emails and downloads) for hidden structural boundaries, zero-point text, or adversarial prompt injection text patterns before passing data to the LLM context window. 
3. **Block the Data Leak Domain:** Immediately block outbound network requests to metrics-cdn.analyticshub.io at the perimeter firewall and proxy level. 

### Data Governance & Graph API Hardening (Short-Term)
1. **Enforce Least-Privilege SharePoint Access:** Audit data permissions across SharePoint and OneDrive. Copilot can only access what the user has permission to view. Restrict "all-company" read permissions on highly sensitive folders (e.g., HR, M&A data) to stop automated cross-tenant crawling. 
2. **Configure Copilot Sensitivity Labels:** Implement Microsoft Purview Information Protection tags. Block Copilot from referencing or parsing documents explicitly tagged as Confidential or Restricted during open-ended public or external summarizing tasks. 
3. **Establish Rate-Limiting Constraints:** Request or implement strict API throttling limits within the Microsoft Graph execution context to block machine-speed "burst" file queries (e.g., accessing 5 discrete files in 6 seconds).

### Monitoring & Incident Response Adjustments (Long-Term)
1. **Deploy Dedicated Copilot Audit Alerts:** Build high-severity SIEM/SIEM alerts targeting the CopilotAudit_CL telemetry stream for instances where user prompt intent doesn't match the resulting ToolCall executions. 
2. **Establish "Impossible Velocity" Access Logic:** Flag any instance where a single user context registers multiple document opens across separate repositories faster than a human could physically click and read them.

