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

### CVE-2026-56164 - Microsoft's July 2026 Patch Tuesday: 570 Vulnerabilities and 3 Zero-Days (risk score: 8/10)
**Vendor/Product:** Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Missing Authentication for Critical Function Vulnerability
**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - Remote code execution vulnerabilities are highly feasible to detect through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules can be tuned to specifically look for signs of remote code execution attempts based on the patterns of these vulnerabilities.

### CVE-2026-56155 - Microsoft's July 2026 Patch Tuesday: 570 Vulnerabilities and 3 Zero-Days (risk score: 8/10)
**Vendor/Product:** Microsoft Active Directory Federation Services
**Vulnerability:** Microsoft Active Directory Federation Services Insufficient Granularity of Access Control Vulnerability 
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

### CVE-2026-60004 - Gitea Gitea
**Vulnerability:** Gitea Code Injection Vulnerability

**MITRE CWE:** CWE-94

**References:** https://github.com/go-gitea/gitea/security/advisories/GHSA-rcr6-4jqh-j84m ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-60004

### CVE-2026-21962 - Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in
**Vulnerability:** Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in Improper Access Control Vulnerability

**MITRE CWE:** CWE-284

**References:** https://www.oracle.com/security-alerts/cpujan2026.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-21962

### CVE-2026-73570 - Synacor Zimbra Collaboration Suite (ZCS)
**Vulnerability:** Zimbra Collaboration Suite (ZCS) OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories ; https://blog.zimbra.com/2026/07/patch-release-update-zimbra-10-1-20/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-73570

### CVE-2026-72530 - TrueConf Server
**Vulnerability:** TrueConf Server Code Injection Vulnerability

**MITRE CWE:** CWE-94

**References:** https://trueconf.com/blog/news/security-fixes-updates-and-advisories ; https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-breakout-from-isolated-environment/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-72530

### CVE-2026-72529 - TrueConf Server
**Vulnerability:** TrueConf Server Missing Authentication for Critical Function Vulnerability

**MITRE CWE:** CWE-306

**References:** https://trueconf.com/blog/news/security-fixes-updates-and-advisories ; https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-missing-authentication-for-critical-function/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-72529

### CVE-2026-64849 - MLflow MLflow
**Vulnerability:** MLflow Server-Side Request Forgery Vulnerability

**MITRE CWE:** CWE-918

**References:** https://github.com/mlflow/mlflow/pull/24258 ; https://github.com/mlflow/mlflow/issues/24179 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-64849

### CVE-2026-33824 - Microsoft Internet Key Exchange (IKE) Service Extensions
**Vulnerability:** Microsoft Internet Key Exchange (IKE) Service Extensions Double Free Vulnerability

**MITRE CWE:** CWE-415

**References:** https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-33824 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-33824

### CVE-2026-59310 - Broadcom VMware vCenter
**Vulnerability:** Broadcom VMware vCenter Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-59310

### CVE-2026-55040 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Weak Authentication Vulnerability

**MITRE CWE:** CWE-1390

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55040 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-55040

### CVE-2026-65400 - Apple macOS
**Vulnerability:** Apple macOS Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://support.apple.com/en-us/148170; https://support.apple.com/en-us/148171; https://support.apple.com/en-us/148172 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-65400

### CVE-2025-62593 - Ray-Project Ray
**Vulnerability:** Ray-Project Ray Code Injection Vulnerability

**MITRE CWE:** CWE-94, CWE-352

**References:** https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v ; https://github.com/ray-project/ray/commit/70e7c72780bdec075dba6cad1afe0832772bfe09 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2025-62593

### CVE-2026-20349 - Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) 
**Vulnerability:** Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) Heap Inspection Vulnerability

**MITRE CWE:** CWE-244

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-vpn-dos-dzv4mQFF ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20349

### CVE-2026-68820 - Microsoft Windows Ancillary Function Driver for WinSock 
**Vulnerability:** Microsoft Windows Ancillary Function Driver for WinSock Use-After-Free Vulnerability

**MITRE CWE:** CWE-416

**References:** https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2026-68820 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-68820

### CVE-2026-72898 - Metabase Metabase
**Vulnerability:** Metabase SQL Injection Vulnerability

**MITRE CWE:** CWE-89

**References:** https://www.metabase.com/blog/security-update ; https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-72898

### CVE-2026-8037 - Progress LoadMaster
**Vulnerability:** Progress LoadMaster Command Injection Vulnerability

**MITRE CWE:** CWE-77

**References:** https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-8037

### CVE-2026-63077 - JetBrains TeamCity
**Vulnerability:** JetBrains TeamCity Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** https://blog.jetbrains.com/teamcity/2026/07/cve-2026-63077/; https://www.jetbrains.com/privacy-security/issues-fixed/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-63077

### CVE-2026-18556 - N-able N-central
**Vulnerability:** N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability

**MITRE CWE:** CWE-288

**References:** https://uptime.n-able.com/ ; https://status.n-able.com/2026/08/02/n-central-2026-3-hotfix-1-mitigation-for-cve-2026-18577/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-18556

### CVE-2026-34486 - Apache Tomcat
**Vulnerability:** Apache Tomcat Missing Encryption of Sensitive Data Vulnerability

**MITRE CWE:** CWE-311

**References:** https://lists.apache.org/thread/9510k5p5zdvt9pkkgtyp85mvwxo2qrly ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-34486

### CVE-2026-9198 - IBM Langflow
**Vulnerability:** IBM Langflow Code Injection Vulnerability

**MITRE CWE:** CWE-94

**References:** https://www.ibm.com/support/pages/node/7278927 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-9198

### CVE-2026-18577 - N-able N-central
**Vulnerability:** N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability

**MITRE CWE:** CWE-288

**References:** https://documentation.n-able.com/N-central/Release_Notes/GA/Content/N-central_2026.3_HF1_Release_Notes.htm ; https://status.n-able.com/2026/08/02/n-central-2026-3-hotfix-1-mitigation-for-cve-2026-18577/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-18577

### CVE-2026-20316 - Cisco Secure Firewall Management Center (FMC)
**Vulnerability:** Cisco Secure Firewall Management Center Use of Hard-coded Password Vulnerability

**MITRE CWE:** CWE-259

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-static-cred-BET3Cjh ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20316

### CVE-2025-68686 - Fortinet FortiOS
**Vulnerability:** Fortinet FortiOS Exposure of Sensitive Information to an Unauthorized Actor Vulnerability

**MITRE CWE:** CWE-200

**References:** https://fortiguard.fortinet.com/psirt/FG-IR-25-934 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2025-68686

### CVE-2026-16812 - Arista VeloCloud Orchestrator
**Vulnerability:** Arista VeloCloud Orchestrator On-Prem OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://www.arista.com/en/support/advisories-notices/security-advisory/24364-security-advisory-0144 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-16812

### CVE-2026-16232 - Check Point SmartConsole
**Vulnerability:** Check Point SmartConsole Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://support.checkpoint.com/results/sk/sk185169/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-16232

### CVE-2026-50522 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Deserialization of Untrusted Data Vulnerability 

**MITRE CWE:** CWE-502

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50522 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-50522

### CVE-2026-60137 - WordPress Core
**Vulnerability:** WordPress Core SQL Injection Vulnerability

**MITRE CWE:** CWE-89

**References:** https://wordpress.org/news/2026/07/wordpress-7-0-2-release/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-60137

### CVE-2026-63030 - WordPress Core
**Vulnerability:** WordPress Core Interpretation Conflict Vulnerability

**MITRE CWE:** CWE-436

**References:** https://wordpress.org/news/2026/07/wordpress-7-0-2-release/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-63030

### CVE-2026-0770 - Langflow Langflow
**Vulnerability:** Langflow Inclusion of Functionality from Untrusted Control Sphere Vulnerability

**MITRE CWE:** CWE-829

**References:** https://github.com/langflow-ai/langflow/releases/tag/v1.9.0 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-0770 

### CVE-2021-27137 - DD-WRT DD-WRT
**Vulnerability:** DD-WRT Stack-Based Buffer Overflow Vulnerability

**MITRE CWE:** CWE-121

**References:** This vulnerability affects a common open-source component, third-party library, proprietary implementation, or a protocol used by different products. Please check with specific vendors for information on patching status. For more information, please see: https://svn.dd-wrt.com/changeset/45724 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2021-27137

### CVE-2026-58644 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58644 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-58644
