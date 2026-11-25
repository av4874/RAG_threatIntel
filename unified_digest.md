# Unified Threat Digest

## Dual-Confirmed (RAG article + CISA KEV)

### CVE-2026-56164 - Microsoft July 2026 Patch Tuesday: Record 622 Vulnerabilities with Two Active Zero-Days (risk score: 9/10)
**Vendor/Product:** Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Missing Authentication for Critical Function Vulnerability
**ATT&CK Technique:** T1136 - Create Account
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows unauthenticated attackers to escalate privileges, which can be detected through security event logs and endpoint monitoring.
**Recommendation:** Tune existing rule - Existing rules can be tuned to detect unusual network activity indicative of privilege escalation attempts.

### CVE-2026-15409 - SonicWall SMA1000 Zero-Day Vulnerabilities: Full Technical Details (risk score: 10/10)
**Vendor/Product:** SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability
**ATT&CK Technique:** T1089 - System Network Connections Discovery (UNVERIFIED)
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for command execution and request manipulation, which can be detected through network connection logs.
**Recommendation:** New use case - Implement new rules to monitor for unusual network connections and command executions.

### CVE-2026-15410 - SonicWall SMA1000 Zero-Day Vulnerabilities: Full Technical Details (risk score: 10/10)
**Vendor/Product:** SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances Code Injection Vulnerability
**ATT&CK Technique:** T1089 - System Network Connections Discovery (UNVERIFIED)
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for command execution and request manipulation, which can be detected through network connection logs.
**Recommendation:** New use case - Implement new rules to monitor for unusual network connections and command executions.

### CVE-2026-56155 - Microsoft's July 2026 Patch Tuesday: 570 Vulnerabilities and 3 Zero-Days (risk score: 8/10)
**Vendor/Product:** Microsoft Active Directory Federation Services
**Vulnerability:** Microsoft Active Directory Federation Services Insufficient Granularity of Access Control Vulnerability
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - Remote code execution vulnerabilities are highly feasible to detect through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules can be tuned to specifically look for signs of remote code execution attempts based on the patterns of these vulnerabilities.

### CVE-2026-56164 - Microsoft's July 2026 Patch Tuesday: 570 Vulnerabilities and 3 Zero-Days (risk score: 8/10)
**Vendor/Product:** Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Missing Authentication for Critical Function Vulnerability
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - Remote code execution vulnerabilities are highly feasible to detect through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules can be tuned to specifically look for signs of remote code execution attempts based on the patterns of these vulnerabilities.

## RAG-Only High-Risk (not in CISA KEV)

### ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files (risk score: 8/10)
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The attack vector involves pasting a command into the Run box, which can be detected in security event logs and EDR/endpoint logs.
**Recommendation:** Tune existing rule - Existing rules for detecting obfuscated commands can be tuned to catch this specific behavior.

### Fake Coding Tests Deliver OtterCookie-Aligned Malware Hidden in SVG Flag Images (risk score: 8/10)
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Web server access logs, EDR/endpoint logs
**Detection Feasibility:** Medium - Detection is possible but requires specific knowledge of the steganographic technique used.
**Recommendation:** Tune existing rule - Existing rules can be tuned to look for anomalies in SVG files or unusual network traffic patterns associated with steganography.

### HollowByte DDoS flaw bloats OpenSSL server memory with 11-byte payload (risk score: 8/10)
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, Web server access logs, Firewall/VPN logs
**Detection Feasibility:** High - The attack can be detected through network traffic and security event logs.
**Recommendation:** Tune existing rule - Existing DoS detection rules can be fine-tuned to identify and mitigate this specific attack vector.

### Inc Ransomware Exploits SonicWall SMA Zero-Days (risk score: 8/10)
**ATT&CK Technique:** T1548 - Abuse Elevation Control Mechanism
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for gaining root-level capabilities, which can be detected through security event logs and firewall activity.
**Recommendation:** New use case - This is a new exploit targeting specific vulnerabilities, requiring a new detection mechanism.

### Microsoft warns of surge in ACR Stealer attacks on customers (risk score: 8/10)
**ATT&CK Technique:** T1110 - Brute Force
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The attack targets browser-stored credentials and can be detected through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules for credential dumping can be tuned to detect ACR Stealer activity based on known indicators of compromise.

### New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Tokens (risk score: 8/10)
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Cloud audit logs, EDR/endpoint logs
**Detection Feasibility:** High - The botnet is actively scanning and attempting to exploit exposed AI services, which can be detected through cloud audit logs and endpoint security logs.
**Recommendation:** Tune existing rule - Existing security controls should be tuned to detect and respond to brute force attempts on exposed AI services.

### New Windows LegacyHive zero-day gives hackers admin privileges (risk score: 8/10)
**ATT&CK Technique:** T1548 - Abuse Elevation Control Mechanism
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The exploit allows privilege escalation, which is a common attack vector and can be detected through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules for privilege escalation can be tuned to detect this specific exploit based on the behavior described.

### New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code (risk score: 10/10)
**ATT&CK Technique:** T1089 - Web Shell (UNVERIFIED)
**Log Sources:** Web server access logs, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows unauthenticated attackers to execute code, making it highly feasible for an attacker to exploit.
**Recommendation:** New use case - A new detection rule is needed to identify potential web shell activity on affected WordPress sites.

### Seven Malicious Vite npm Packages Use Blockchain C2 to Deliver a RAT (risk score: 8/10)
**ATT&CK Technique:** T1071 - Application Layer Protocol
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The use of a blockchain-based C2 infrastructure indicates the attackers are leveraging command execution techniques, which can be detected through endpoint security and Windows security logs.
**Recommendation:** Tune existing rule - Existing EDR rules can be tuned to detect unusual outbound network traffic patterns associated with blockchain-based C2 communications.

### Update now: 7-Zip fixes RCE flaw exploitable with malicious archives (risk score: 8/10)
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability can be exploited through specially crafted compressed files, which can be detected by monitoring security event logs and endpoint activity.
**Recommendation:** New use case - Implementing a new detection rule to monitor for suspicious file openings and network activities associated with 7-Zip usage.

### WordPress Core "wp2shell" RCE flaws get public exploits, patch now (risk score: 8/10)
**ATT&CK Technique:** T1059 - Command and Scripting Interpreter
**Log Sources:** Windows Security Event Log, Web server access logs, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows remote code execution, which can be detected through security event logs and endpoint logs.
**Recommendation:** Tune existing rule - Existing security solutions can likely detect malicious activities related to command execution based on known indicators of compromise.

## KEV-Only (not covered by RAG lane)

### CVE-2026-103406 - Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router
**Vulnerability:** Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://supportportal.juniper.net/s/article/2026-10-On-Demand-Security-Bulletin-Session-Smart-Router-and-Session-Smart-Conductor-Multiple-internally-discovered-vulnerabilities-resolved ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-103406

### CVE-2026-132224 - Optimizely Web Experimentation
**Vulnerability:** Optimizely Web Experimentation External Control of Critical State Data Vulnerability

**MITRE CWE:** CWE-642

**References:** https://pages.optimizely.com/rs/947-RKE-048/images/Security%20Incident%20Report%20-%20Optimizely%20Web%20Experimentation%20-%20Nov%2017%202026.pdf ; https://status.optimizely.com/incidents/ftw0fh9wx43z ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-132224

### CVE-2026-131914 - Idunno AntiCsrf
**Vulnerability:** Idunno AntiCsrf Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-131914

### CVE-2026-132165 - Drupal Core
**Vulnerability:** Drupal Core Remote Code Execution Vulnerability

**MITRE CWE:** CWE-636

**References:** https://www.drupal.org/sa-core-2026-017 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-132165

### CVE-2026-133968 - Project MONAI MONAI Label
**Vulnerability:** Project MONAI MONAI Label Path Traversal Vulnerability

**MITRE CWE:** CWE-24

**References:** https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94 ; https://github.com/Project-MONAI/MONAILabel/pull/1915 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-133968

### CVE-2026-134624 - N-able MailAssure
**Vulnerability:** N-able MailAssure (SpamExperts) Server-Side Request Forgery (SSRF) Vulnerability

**MITRE CWE:** CWE-918

**References:** https://me.n-able.com/s/security-advisory/aArVy0000002mrlKAA ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-134624

### CVE-2026-129448 - Apache Roller
**Vulnerability:** Apache Roller Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** https://lists.apache.org/thread/cc0jck13nb9vvcmzxzwotr6n16mx28z9 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-129448

### CVE-2026-123890 - Broadcom VMware vCenter
**Vulnerability:** VMWare vCenter Authentication Bypass Using an Alternate Path or Channel Vulnerability

**MITRE CWE:** CWE-288

**References:** https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-123890

### CVE-2025-42884 - SAP NetWeaver
**Vulnerability:** SAP NetWeaver Improper Neutralization of Special Elements in Data Query Logic Vulnerability

**MITRE CWE:** CWE-943

**References:** https://support.sap.com/en/my-support/knowledge-base/security-notes-news/bulletin-2025.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2025-42884

### CVE-2026-76466 - Cisco Expressway Series
**Vulnerability:** Cisco Expressway Series Use of Hard-coded Credentials Vulnerability

**MITRE CWE:** CWE-798

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vcs-static-cred-hr7EWZ8t ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-76466

### CVE-2024-10441 - Synology DiskStation Manager (DSM) (RANSOMWARE-LINKED)
**Vulnerability:** Synology DiskStation Manager (DSM) Improper Encoding or Escaping of Output Vulnerability

**MITRE CWE:** CWE-116

**References:** https://www.synology.com/zh-tw/security/advisory/Synology_SA_24_20 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2024-10441

### CVE-2026-40217 - BerriAI LiteLLM
**Vulnerability:** BerriAI LiteLLM Unprotected Alternate Channel Vulnerability

**MITRE CWE:** CWE-420

**References:** https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-40217

### CVE-2026-90817 - Vanderbilt University Research Electronic Data Capture (REDCap)
**Vulnerability:** Vanderbilt University Research Electronic Data Capture (REDCap) Code Injection Vulnerability

**MITRE CWE:** CWE-73, CWE-94

**References:** https://projectredcap.org/resources/community ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-90817

### CVE-2026-90436 - Apache Axis
**Vulnerability:** Apache Axis Unsafe Reflection Vulnerability

**MITRE CWE:** CWE-470

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: ; https://lists.apache.org/thread/8slf0j9gz35z56t0glt5h0ncwlbn4bdz ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-90436

### CVE-2026-115731 - Perforce Puppet Enterprise
**Vulnerability:** Perforce Puppet Enterprise Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502, CWE-94

**References:** https://portal.perforce.com/s/cve/a91Qi000003IaHpIAK/report-deserialization-code-execution ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-115731

### CVE-2026-114713 - UnrealIRCd UnrealIRCd
**Vulnerability:** UnrealIRCd Improper Neutralization of Delimiters Vulnerability

**MITRE CWE:** CWE-140

**References:** https://forums.unrealircd.org/viewtopic.php?t=9487 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-114713

### CVE-2026-123039 - Check Point Multiple Products
**Vulnerability:** Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability

**MITRE CWE:** CWE-732, CWE-862

**References:** https://support.checkpoint.com/results/sk/sk1000362 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-123039

### CVE-2026-124194 - Microsoft Office
**Vulnerability:** Microsoft Office Outlook Missing User Interaction for Potentially Unsafe Action Vulnerability

**MITRE CWE:** CWE-356

**References:** https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-124194 ; https://nvd.nist.gov/vuln/detail/CVE-2026-124194

### CVE-2026-111793 - Openwave Messaging Limited Webtop Media Transcoder
**Vulnerability:** Openwave Messaging Limited Webtop Media Transcoder Incorrect Resource Transfer Between Spheres Vulnerability

**MITRE CWE:** CWE-669

**References:** https://github.com/GISOpenwave/security-advisories-public/blob/main/CAN-2026-2032674.md ; https://jvn.jp/en/vu/JVNVU93403064/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-111793

### CVE-2026-20320 - Cisco BroadWorks
**Vulnerability:** Cisco BroadWorks Improper Restriction of XML External Entity Reference Vulnerability

**MITRE CWE:** CWE-611

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bworks-xxe-uwUd7CEt ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20320

### CVE-2026-111560 - Barracuda Networks Multiple Products
**Vulnerability:** Barracuda Networks Multiple Products OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection ; https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0041.md ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-111560

### CVE-2026-116606 - Barracuda Networks Barracuda Email Security Gateway (ESG)
**Vulnerability:** Barracuda Networks Email Security Gateway (ESG) Authentication Bypass Using an Alternate Path or Channel Vulnerability

**MITRE CWE:** CWE-288

**References:** https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection ; https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0042.md ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-116606

### CVE-2026-125350 - Google Chromium
**Vulnerability:** Google Chromium Use-After-Free Vulnerability

**MITRE CWE:** CWE-416

**References:** https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_018223192.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-125350

### CVE-2026-102895 - GPUStack GPUStack
**Vulnerability:** GPUStack Improper Authentication Vulnerability

**MITRE CWE:** CWE-287, CWE-290, CWE-346

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: ; https://github.com/gpustack/gpustack/security/advisories/GHSA-gj9m-f8ph-pmhr ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-102895

### CVE-2026-123158 - OpenBSD OpenSSH
**Vulnerability:** OpenBSD OpenSSH Unexpected Status Code or Return Value Vulnerability

**MITRE CWE:** CWE-394

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://www.openssh.org/releasenotes.html ; https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/ ; https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-123158

### CVE-2026-116779 - SignalWire FreeSwitch
**Vulnerability:** SignalWire FreeSwitch Code Injection Vulnerability

**MITRE CWE:** CWE-77, CWE-78, CWE-749

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/signalwire/freeswitch/security/advisories/GHSA-mg63-h38w-8p9p ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-116779

### CVE-2026-123218 - IBM Aspera Faspex
**Vulnerability:** IBM Aspera Faspex Incorrect Authorization Vulnerability

**MITRE CWE:** CWE-863

**References:** https://www.ibm.com/support/pages/node/7295921 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-123218

### CVE-2026-19868 - SonicWall SonicOS SSLVPN
**Vulnerability:** SonicWall SonicOS SSLVPN Use of Single-factor Authentication Vulnerability

**MITRE CWE:** CWE-308

**References:** https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-19868

### CVE-2024-27834 - Apple Multiple Products
**Vulnerability:** Apple Multiple Products Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://support.apple.com/en-us/120896 ; https://support.apple.com/en-us/120898 ; https://support.apple.com/en-us/120901 ; https://support.apple.com/en-us/120902 ; https://support.apple.com/en-us/120903 ; https://support.apple.com/en-us/120905 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2024-27834

### CVE-2026-119977 - WordPress WordPress Core
**Vulnerability:** WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability

**MITRE CWE:** CWE-367

**References:** https://wordpress.org/news/2026/10/wordpress-7-1-4 ; https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-713-unauthenticated-upgrade-window-staged-installer-remote-code-execution ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-119977
