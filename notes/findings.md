# Phishing Email Investigation – Findings

## Overview

A suspicious email impersonating Coinbase support was analyzed after being flagged by email security controls and user suspicion. The message contained a Microsoft Word attachment and multiple indicators consistent with a targeted phishing attempt delivering a malicious payload.

The analysis focused on sender authenticity, email authentication results, spam classification, and attachment reputation.

---

## Indicators Observed

### 1. Sender Impersonation

The email displayed a sender name suggesting it originated from Coinbase support, but the actual sending address and return-path did not belong to Coinbase infrastructure.

- Displayed From address differed from Return-Path
- Sending domain was unrelated to Coinbase

This indicates domain spoofing and impersonation of a trusted brand.

---

### 2. Email Authentication Failures

| Control | Result |
|--------|---------|
| SPF | Fail |
| DKIM | Fail / None |
| DMARC | Fail |

These failures indicate the sender domain is not authorized to send email on behalf of the claimed sender and that the message was not cryptographically authenticated.

---

### 3. Spam, Bulk, and Phishing Classification

| Metric | Value | Interpretation |
|--------|-------|----------------|
| SCL | 5 | Likely spam |
| BCL | 0 | Not a bulk campaign |
| PCL | 5 | High confidence phishing |

The low BCL combined with elevated SCL and PCL indicates that this was not a mass spam campaign but a targeted phishing attempt designed to deceive specific recipients.

---

### 4. Malicious Attachment

The email contained a Microsoft Word attachment:

- Filename: `Coinbase -15392.docx`
- Type: Office document attachment

The attachment hash was submitted to VirusTotal and was flagged by 21 out of 67 security vendors as malicious, with classifications including phishing and trojan.

This strongly indicates the attachment is malicious and part of the attack chain.

---

## Risk Assessment

| Category | Impact |
|---------|---------|
| Confidentiality | High |
| Integrity | Medium |
| Availability | Low |

The attachment could result in credential theft, malware execution, or unauthorized access if opened by a recipient.

**Overall Risk Level:** High

---

## Recommended Response

### Immediate Actions

- Quarantine and remove the email from all mailboxes.
- Block the sending domain and associated infrastructure.
- Block the attachment hash at the email gateway and endpoint security tools.
- Scan endpoints for signs of execution.

### Follow-Up Actions

- Reset credentials for any users who interacted with the message or attachment.
- Enable or enforce DMARC policy on protected domains.
- Provide phishing awareness training to users.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing Attachment | T1566.001 |
| Execution | User Execution | T1204 |
| Defense Evasion | Obfuscated / Malicious Content | T1027 |
| Credential Access | Credential Harvesting | T1556 |

---

## Conclusion

This email exhibits multiple high-confidence indicators of phishing, including sender impersonation, authentication failures, targeted delivery, and a confirmed malicious attachment. It represents a credible threat to the organization and warrants immediate remediation and defensive action.
