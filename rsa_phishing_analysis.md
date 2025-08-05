#  RSA Phishing Email Analysis Report

##  Summary
This report analyzes a **real-world spear-phishing email** used in the 2011 **RSA Security Breach**, where attackers targeted employees using a deceptive internal-looking email containing a malicious `.xls` attachment. The analysis includes email headers, phishing indicators, and tool-based insights from MXToolbox, VirusTotal, and PhishTool.

---

##  Phishing Email Sample

From: Recruitment Department recruitment@rsa.com
To: employee@rsa.com
Subject: 2021 Recruitment Plan

I forward this file to you for review. Please open and view it.

    Recruitment Team

Attachment: Recruitment_Plan_2021.xls

---

##  Why It's Suspicious

| Indicator | Reason |
|----------|--------|
| Generic Subject | Common bait for office users |
| Looks Internal | Uses a spoofed RSA domain |
| Malicious Attachment | `.xls` file contained a Flash exploit |
| Short Body | Avoids details to reduce suspicion |
| Reply-To Mismatch | Reply goes to `attacker@malicious.com` |

---

##  Email Header Analysis (MXToolbox)

 **Tool Used:** [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)  
 Screenshot: [`screenshots/mxtoolbox_header_result.png`](./screenshots/mxtoolbox_header_result.png)

**Key Points Identified:**
- `Received From`: `suspicious-host.com (203.0.113.55)`
- **Reply-To**: `attacker@malicious.com`
- **SPF/DKIM**: Missing/Invalid (not trusted source)

---

## Link Analysis (VirusTotal)

 **URL Used:** `http://recruitment.rsa-flash-update.com`  
 Screenshot: [`screenshots/virustotal_fake_link.png`](./screenshots/virustotal_fake_link.png)

**Results:**
- **0/97 vendors flagged** the URL (could be newly created)
- ⚠️ Real attackers use fresh domains to evade detection

---

##  PhishTool Report

 **Tool Used:** [PhishTool Analyzer](https://www.phishtool.com/)  
Screenshot: [`screenshots/phishtool_result.png`](./screenshots/phishtool_result.png)

**Findings:**
- Sender: `recruitment@rsa.com`
- Attachment: `Recruitment_Plan_2021.xls`
- Message body was brief and generic
- No DKIM/SPF/headers found — strong indication of spoofing

---

##  Real-World Impact

- In **2011**, RSA employees received this phishing email.
- The `.xls` exploited a **Flash vulnerability** upon opening.
- Attackers gained **remote access**, moved laterally, and **stole SecurID token-related data**.
- These tokens were used by **defense contractors**, leading to a **massive national security concern**.

 Reference: [RSA Breach Report (Wikipedia)](https://en.wikipedia.org/wiki/Security_breach_of_RSA_SecurID)

---

## What I Learned

- How to **manually detect phishing indicators**
- How to use **tools like MXToolbox, VirusTotal, PhishTool**
- How **minor signs** (like a `Reply-To`) reveal big threats
- How **real-world attacks** happen using simple emails

---

##  Supporting Files

| File | Description |
|------|-------------|
| `rsa_phishing_email.txt` | Original phishing email |
| `email_header_simulation.txt` | Simulated header used in MXToolbox |
| `README.md` | Task overview and submission |
| `screenshots/` | Screenshots of tool output |

---

## Conclusion

This spear-phishing campaign proves that **even well-trained organizations like RSA can fall victim** if attackers craft convincing internal-looking emails. Analyzing headers, link sources, and email content is **critical for threat detection**.


