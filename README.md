# Phishing Email Investigation Lab

## Description

This lab demonstrates the investigation of a real phishing email using raw header analysis, threat intelligence platforms, and attachment inspection to simulate a Tier-1 SOC phishing triage workflow.

---

## Tools Used

- VirusTotal
- AbuseIPDB
- PowerShell (`Get-FileHash`)
- Raw email header analysis

---

## Data Source

Public phishing sample obtained from GitHub in `.eml` format.

---

## Lab Workflow

1. Extracted and reviewed email headers
2. Verified sender authentication (SPF/DKIM/DMARC)
3. Identified sender spoofing and impersonation
4. Analyzed attachment hash via VirusTotal
5. Documented indicators and mapped to MITRE ATT&CK

---

## Key Findings

- Sender impersonates Coinbase
- Authentication controls failed
- Attachment flagged as phishing trojan
- Targeted attack (not bulk spam)
- Subject obfuscation used to evade filters

---

## Indicators of Compromise

| Type | Value |
|------|--------|
| Sender Domain | medisept.com.au |
| Sending IP | 40.107.215.72 |
| Attachment | Coinbase -15392.docx |
| Hash | Generated locally |

---

## Learning Objectives

- Identify phishing indicators
- Perform email header analysis
- Use threat intelligence platforms
- Apply MITRE ATT&CK mapping

---

## Future Improvements

- Add Splunk detections and alerts based on identified indicators
- Simulate user interaction and endpoint execution
- Correlate email telemetry with endpoint and authentication logs
- Expand analysis with additional phishing samples

---

## Disclaimer

This project uses lab-generated and public sample data for educational and portfolio purposes only.
