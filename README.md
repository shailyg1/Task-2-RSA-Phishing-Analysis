# 🛡 Task 2 - RSA Phishing Attack Analysis (Elevate Labs Cybersecurity Internship)

## Objective
The objective of this task is to analyze a **real-world spear-phishing email** that was part of the **RSA 2011 breach** — one of the most well-known cyberattacks in history. The goal was to identify **phishing indicators** manually and verify them using **professional cybersecurity tools**.

This task helped simulate **real-world incident analysis** and train us in detecting phishing threats used against large enterprises.

---

##  Why This Task is Unique

Unlike generic simulations, this task uses the **actual phishing email** involved in the 2011 **RSA breach**, which compromised sensitive SecurID token data used by U.S. defense contractors.

Analyzing this email not only enhances technical skills, but also shows how **simple attacks can lead to massive breaches** when overlooked.

---

##  Tools Used

| Tool        | Purpose                                  | Link                                   |
|-------------|------------------------------------------|----------------------------------------|
| MXToolbox   | Header analysis                          | [mxtoolbox.com](https://mxtoolbox.com/) |
| VirusTotal  | URL reputation check                     | [virustotal.com](https://virustotal.com/) |
| PhishTool   | Email structure and metadata analysis    | [phishtool.com](https://www.phishtool.com/) |

---

##  Phishing Email Overview

```text
From: Recruitment Department <recruitment@rsa.com>
To: <employee@rsa.com>
Subject: 2021 Recruitment Plan

I forward this file to you for review. Please open and view it.

- Recruitment Team

Attachment: Recruitment_Plan_2021.xls

 The .xls file attached contained a malicious Flash exploit that, when opened, gave attackers remote access to the employee's system. From there, they penetrated RSA’s internal systems and exfiltrated 2FA token data.
 What We Did
 Manual Indicators of Phishing:

    Spoofed sender address: recruitment@rsa.com

    Short, vague content to trick the user

    Malicious attachment: Excel file with Flash vulnerability

    Reply-To mismatch: (used in simulated headers)

Tool-Based Verification:

    MXToolbox:

        Analyzed custom header using fake domain + malicious IP.

         Revealed forged From address and suspicious Reply-To.

         Screenshot: screenshots/mxtoolbox_header_result.png

    VirusTotal:

        Scanned the fake phishing link: http://recruitment.rsa-flash-update.com

         Showed that link wasn't flagged yet (real-world tactic!)

         Screenshot: screenshots/virustotal_fake_link.png

    PhishTool:

        Parsed email layout and metadata.

         Helped visualize content + missing authentication fields.

         Screenshot: screenshots/phishtool_result.png

 Repository Structure

Task-2-RSA-Phishing-Analysis/
├── rsa_phishing_email.txt             # Raw email used for analysis
├── email_header_simulation.txt        # Simulated email header with attacker IP
├── rsa_phishing_analysis.md           # Full technical report
├── README.md                          # Task summary and context
└── screenshots/
    ├── mxtoolbox_header_result.png
    ├── virustotal_fake_link.png
    └── phishtool_result.png

 Learnings from This Task

✅ How real phishing emails look inside
✅ How attackers spoof trusted domains
✅ Why header analysis is critical in investigation
✅ How to use VirusTotal, MXToolbox, and PhishTool effectively
✅ How small oversights (like vague email + malicious link) can lead to nation-level cyber incidents
