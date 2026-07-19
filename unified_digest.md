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

### CVE-2026-58644 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Deserialization of Untrusted Data Vulnerability

### CVE-2026-25089 - Fortinet FortiSandbox
**Vulnerability:** Fortinet FortiSandbox OS Command Injection Vulnerability

### CVE-2026-39808 - Fortinet FortiSandbox
**Vulnerability:** Fortinet FortiSandbox OS Command Injection Vulnerability

### CVE-2026-46817 - Oracle E-Business Suite
**Vulnerability:** Oracle E-Business Suite Improper Privilege Management Vulnerability

### CVE-2023-4346 - KNX Association KNX Protocol Connection Authorization Option 1
**Vulnerability:** KNX Association KNX Protocol Connection Authorization Option 1 Overly Restrictive Account Lockout Mechanism Vulnerability

### CVE-2008-4128 - Cisco IOS
**Vulnerability:** Cisco IOS Cross-Site Request Forgery Vulnerability

### CVE-2026-56291 - Balbooa Forms
**Vulnerability:** Balbooa Forms Unrestricted Upload of File with Dangerous Type Vulnerability

### CVE-2026-48939 - iCagenda iCagenda
**Vulnerability:** iCagenda Unrestricted Upload of File with Dangerous Type Vulnerability

### CVE-2026-48908 - JoomShaper SP Page Builder
**Vulnerability:** JoomShaper SP Page Builder Unrestricted Upload of File with Dangerous Type Vulnerability

### CVE-2026-55255 - Langflow Langflow
**Vulnerability:** Langflow Authorization Bypass Through User-Controlled Key Vulnerability

### CVE-2026-56290 - Joomlack Page Builder
**Vulnerability:** Joomlack Page Builder Improper Access Control Vulnerability

### CVE-2026-48282 - Adobe ColdFusion
**Vulnerability:** Adobe ColdFusion Path Traversal Vulnerability

### CVE-2026-45659 - Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability

### CVE-2026-48558 - SimpleHelp  SimpleHelp
**Vulnerability:** SimpleHelp Authentication Bypass Vulnerability

### CVE-2026-12569 - PTC Windchill and FlexPLM
**Vulnerability:** PTC Windchill and FlexPLM Improper Input Validation Vulnerability

### CVE-2026-20230 - Cisco Unified Communications Manager
**Vulnerability:** Cisco Unified Communications Manager Server-Side Request Forgery (SSRF) Vulnerability

### CVE-2025-67038 - Lantronix EDS5000
**Vulnerability:** Lantronix EDS5000 Code Injection Vulnerability

### CVE-2026-34910 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Improper Input Validation Vulnerability

### CVE-2026-34909 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Path Traversal Vulnerability

### CVE-2026-34908 - Ubiquiti UniFi OS
**Vulnerability:** Ubiquiti UniFi OS Improper Access Control Vulnerability

### CVE-2026-20253 - Splunk Enterprise
**Vulnerability:** Splunk Enterprise Missing Authentication for Critical Function Vulnerability

### CVE-2026-48907 - Widget Factory Joomla Content Editor 
**Vulnerability:** Widget Factory Joomla Content Editor Improper Access Control Vulnerability

### CVE-2026-54420 - LiteSpeed cPanel Plugin
**Vulnerability:** LiteSpeed cPanel Plugin UNIX Symbolic Link (Symlink) Following Vulnerability

### CVE-2026-20262 - Cisco Catalyst SD-WAN Manager
**Vulnerability:** Cisco Catalyst SD-WAN Manager Directory or Path Traversal Vulnerability

### CVE-2026-35273 - Oracle  PeopleSoft Enterprise PeopleTools (RANSOMWARE-LINKED)
**Vulnerability:** Oracle PeopleSoft Enterprise PeopleTools Missing Authentication for Critical Function Vulnerability

### CVE-2026-10520 - Ivanti Sentry
**Vulnerability:** Ivanti Sentry OS Command Injection Vulnerability

### CVE-2026-11645 - Google Chromium V8
**Vulnerability:** Google Chromium V8 Out-of-Bounds Read and Write Vulnerability

### CVE-2026-7473 - Arista Extensible Operating System
**Vulnerability:** Arista Extensible Operating System Incomplete Comparison with Missing Factors Vulnerability

### CVE-2026-20245 - Cisco Catalyst SD-WAN Manager
**Vulnerability:** Cisco Catalyst SD-WAN Manager Improper Encoding or Escaping of Output Vulnerability

### CVE-2026-50751 - Check Point Security Gateway (RANSOMWARE-LINKED)
**Vulnerability:** Check Point Security Gateway Improper Authentication Vulnerability
