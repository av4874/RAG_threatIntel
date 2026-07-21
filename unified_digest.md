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

### CVE-2026-58644 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58644 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-58644

### CVE-2026-25089 - Fortinet FortiSandbox
**Vulnerability:** Fortinet FortiSandbox OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://fortiguard.fortinet.com/psirt/FG-IR-26-141 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-25089

### CVE-2026-39808 - Fortinet FortiSandbox
**Vulnerability:** Fortinet FortiSandbox OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://fortiguard.fortinet.com/psirt/FG-IR-26-100 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-39808

### CVE-2026-46817 - Oracle E-Business Suite
**Vulnerability:** Oracle E-Business Suite Improper Privilege Management Vulnerability

**MITRE CWE:** CWE-269, CWE-287, CWE-306

**References:** https://www.oracle.com/security-alerts/cspumay2026.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-46817

### CVE-2023-4346 - KNX Association KNX Protocol Connection Authorization Option 1
**Vulnerability:** KNX Association KNX Protocol Connection Authorization Option 1 Overly Restrictive Account Lockout Mechanism Vulnerability

**MITRE CWE:** CWE-645

**References:** https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2023-4346

### CVE-2008-4128 - Cisco IOS
**Vulnerability:** Cisco IOS Cross-Site Request Forgery Vulnerability

**MITRE CWE:** CWE-352

**References:** https://www.cisco.com/c/en/us/obsolete/ios-nx-os-software/cisco-ios-software-releases-12-4-mainline.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2008-4128

### CVE-2026-56291 - Balbooa Forms
**Vulnerability:** Balbooa Forms Unrestricted Upload of File with Dangerous Type Vulnerability

**MITRE CWE:** CWE-434

**References:** https://www.balbooa.com/joomla-forms ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-56291

### CVE-2026-48939 - iCagenda iCagenda
**Vulnerability:** iCagenda Unrestricted Upload of File with Dangerous Type Vulnerability

**MITRE CWE:** CWE-434

**References:** https://www.icagenda.com/#download ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48939

### CVE-2026-48908 - JoomShaper SP Page Builder
**Vulnerability:** JoomShaper SP Page Builder Unrestricted Upload of File with Dangerous Type Vulnerability

**MITRE CWE:** CWE-434

**References:** https://extensions.joomla.org/extension/sp-page-builder/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48908

### CVE-2026-55255 - Langflow Langflow
**Vulnerability:** Langflow Authorization Bypass Through User-Controlled Key Vulnerability

**MITRE CWE:** CWE-639

**References:** https://github.com/langflow-ai/langflow/security/advisories/GHSA-qrpv-q767-xqq2 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-55255

### CVE-2026-56290 - Joomlack Page Builder
**Vulnerability:** Joomlack Page Builder Improper Access Control Vulnerability

**MITRE CWE:** CWE-284

**References:** https://www.joomlack.fr/en/joomla-extensions/page-builder-ck ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-56290

### CVE-2026-48282 - Adobe ColdFusion
**Vulnerability:** Adobe ColdFusion Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** https://helpx.adobe.com/security/products/coldfusion/apsb26-68.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48282

### CVE-2026-45659 - Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45659 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-45659

### CVE-2026-48558 - SimpleHelp  SimpleHelp
**Vulnerability:** SimpleHelp Authentication Bypass Vulnerability

**MITRE CWE:** CWE-347

**References:** https://simple-help.com/security/simplehelp-security-update-2026-05 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48558

### CVE-2026-12569 - PTC Windchill and FlexPLM
**Vulnerability:** PTC Windchill and FlexPLM Improper Input Validation Vulnerability

**MITRE CWE:** CWE-20, CWE-502

**References:** https://www.ptc.com/en/support/article/CS473270 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-12569

### CVE-2026-20230 - Cisco Unified Communications Manager
**Vulnerability:** Cisco Unified Communications Manager Server-Side Request Forgery (SSRF) Vulnerability

**MITRE CWE:** CWE-918

**References:** https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssrf-cXPnHcW.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20230

### CVE-2025-67038 - Lantronix EDS5000
**Vulnerability:** Lantronix EDS5000 Code Injection Vulnerability

**MITRE CWE:** CWE-78, CWE-94

**References:** https://ltrxdev.atlassian.net/wiki/spaces/LTRXTS/pages/2538438657/Latest+Firmware+for+the+EDS5000+series+EDS5008+EDS5016+EDS5032 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2025-67038

### CVE-2026-34910 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Improper Input Validation Vulnerability

**MITRE CWE:** CWE-20

**References:** https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-34910

### CVE-2026-34909 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-34909

### CVE-2026-34908 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Improper Access Control Vulnerability

**MITRE CWE:** CWE-284

**References:** https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-34908

### CVE-2026-20253 - Splunk Enterprise
**Vulnerability:** Splunk Enterprise Missing Authentication for Critical Function Vulnerability

**MITRE CWE:** CWE-306

**References:** https://advisory.splunk.com/advisories/SVD-2026-0603 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20253

### CVE-2026-48907 - Widget Factory Joomla Content Editor 
**Vulnerability:** Widget Factory Joomla Content Editor Improper Access Control Vulnerability

**MITRE CWE:** CWE-284

**References:** https://www.joomlacontenteditor.net/news/jce-security-update-and-a-free-patch-for-older-sites ; https://www.joomlacontenteditor.net/support/changelog/editor ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48907

### CVE-2026-54420 - LiteSpeed cPanel Plugin
**Vulnerability:** LiteSpeed cPanel Plugin UNIX Symbolic Link (Symlink) Following Vulnerability

**MITRE CWE:** CWE-61

**References:** https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-54420

### CVE-2026-20262 - Cisco Catalyst SD-WAN Manager
**Vulnerability:** Cisco Catalyst SD-WAN Manager Directory or Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-20262

### CVE-2026-35273 - Oracle  PeopleSoft Enterprise PeopleTools (RANSOMWARE-LINKED)
**Vulnerability:** Oracle PeopleSoft Enterprise PeopleTools Missing Authentication for Critical Function Vulnerability

**MITRE CWE:** CWE-306

**References:** https://www.oracle.com/security-alerts/alert-cve-2026-35273.html ; https://support.oracle.com/signin/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-35273

### CVE-2026-10520 - Ivanti Sentry
**Vulnerability:** Ivanti Sentry OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-10520-CVE-2026-10523?language=en_US ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-10520

### CVE-2026-11645 - Google Chromium V8
**Vulnerability:** Google Chromium V8 Out-of-Bounds Read and Write Vulnerability

**MITRE CWE:** CWE-787, CWE-125

**References:** https://chromereleases.googleblog.com/2026/06/stable-channel-update-for-desktop_0153744567.html ; https://issues.chromium.org/issues/506689381 ; https://nvd.nist.gov/vuln/detail/CVE-2026-11645

### CVE-2026-7473 - Arista Extensible Operating System
**Vulnerability:** Arista Extensible Operating System Incomplete Comparison with Missing Factors Vulnerability

**MITRE CWE:** CWE-1023

**References:** https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137 ; https://nvd.nist.gov/vuln/detail/CVE-2026-7473

### CVE-2026-20245 - Cisco Catalyst SD-WAN Manager
**Vulnerability:** Cisco Catalyst SD-WAN Manager Improper Encoding or Escaping of Output Vulnerability

**MITRE CWE:** CWE-116

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx ; https://nvd.nist.gov/vuln/detail/CVE-2026-20245

### CVE-2026-50751 - Check Point Security Gateway (RANSOMWARE-LINKED)
**Vulnerability:** Check Point Security Gateway Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/ ; https://support.checkpoint.com/results/sk/sk185033?_gl=1*1wqeqhc*_gcl_au*MTI1MzE5MjI2LjE3ODA5MzQ1NTM. ; https://nvd.nist.gov/vuln/detail/CVE-2026-50751
