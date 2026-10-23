# Unified Threat Digest

## Dual-Confirmed (RAG article + CISA KEV)

### CVE-2026-56164 - Microsoft July 2026 Patch Tuesday: Record 622 Vulnerabilities with Two Active Zero-Days (risk score: 9/10)
**Vendor/Product:** Microsoft SharePoint Server
**Vulnerability:** Microsoft SharePoint Server Missing Authentication for Critical Function Vulnerability
**ATT&CK Technique:** T1136 - Create Account
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows unauthenticated attackers to escalate privileges, which can be detected through security event logs and endpoint monitoring.
**Recommendation:** Tune existing rule - Existing rules can be tuned to detect unusual network activity indicative of privilege escalation attempts.

### CVE-2026-15410 - SonicWall SMA1000 Zero-Day Vulnerabilities: Full Technical Details (risk score: 10/10)
**Vendor/Product:** SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances Code Injection Vulnerability
**ATT&CK Technique:** T1089 - System Network Connections Discovery (UNVERIFIED)
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for command execution and request manipulation, which can be detected through network connection logs.
**Recommendation:** New use case - Implement new rules to monitor for unusual network connections and command executions.

### CVE-2026-15409 - SonicWall SMA1000 Zero-Day Vulnerabilities: Full Technical Details (risk score: 10/10)
**Vendor/Product:** SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability
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

### CVE-2026-106931 - EG Secure Solutions SiteGuard Server Edition
**Vulnerability:** EG Secure Solutions SiteGuard Server Edition OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://www.eg-secure.co.jp/siteguard/news/alert-202610-1 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-106931

### CVE-2026-96656 - Plex Media Server
**Vulnerability:** Plex Media Server External Control of File Name or Path Vulnerability

**MITRE CWE:** CWE-73

**References:** https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-96656

### CVE-2026-96655 - Plex Media Server
**Vulnerability:** Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability

**MITRE CWE:** CWE-918

**References:** https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-96655

### CVE-2026-96654 - Plex Media Server
**Vulnerability:** Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability

**MITRE CWE:** CWE-84

**References:** https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-96654

### CVE-2026-96652 - Plex Media Server
**Vulnerability:** Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability

**MITRE CWE:** CWE-918

**References:** https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-96652

### CVE-2026-110936 - Siemens Software Center
**Vulnerability:** Siemens Software Center Uncontrolled Search Path Element Vulnerability

**MITRE CWE:** CWE-427

**References:** https://productcert.siemens.com/productcert/html/ssa-580366.html ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-110936

### CVE-2026-102764 - BeyondTrust Remote Support
**Vulnerability:** BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability

**MITRE CWE:** CWE-290

**References:** https://www.beyondtrust.com/trust-center/security-advisories/bt26-05 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-102764

### CVE-2025-61624 - Fortinet Multiple Products
**Vulnerability:** Fortinet Multiple Products Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** https://fortiguard.fortinet.com/psirt/FG-IR-26-122 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2025-61624

### CVE-2026-21589 - Atlassian Multiple Products
**Vulnerability:** Atlassian Multiple Products Files or Directories Accessible to External Parties Vulnerability

**MITRE CWE:** CWE-552

**References:** https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html?ref=labs.watchtowr.com ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-21589

### CVE-2026-105134 - Ahsay AhsayCBS
**Vulnerability:** Ahsay AhsayCBS Command Injection Vulnerability

**MITRE CWE:** CWE-77, CWE-78

**References:** https://www.ahsay.com/en/company/announcements/patch-cve-105133-105134-update ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-105134

### CVE-2026-76519 - Cisco Secure Email Gateway
**Vulnerability:** Cisco Secure Email Gateway Relative Path Traversal Vulnerability

**MITRE CWE:** CWE-23

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-afw-zqYJkjxp ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-76519

### CVE-2026-105133 - Ahsay AhsayCBS
**Vulnerability:** Ahsay AhsayCBS Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://www.ahsay.com/en/company/announcements/patch-cve-105133-105134-update ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-105133

### CVE-2026-0322 - Palo Alto Networks PAN-OS
**Vulnerability:** Palo Alto Networks PAN-OS Code Injection Vulnerability

**MITRE CWE:** CWE-94

**References:** https://security.paloaltonetworks.com/CVE-2026-0322 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-0322

### CVE-2026-104935 - Ivanti Connect Secure
**Vulnerability:** Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability

**MITRE CWE:** CWE-290

**References:** https:/forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935 ; https://nvd.nist.gov/vuln/detail/CVE-2026-104935

### CVE-2026-96951 - Microsoft Windows
**Vulnerability:** Microsoft Windows Command Injection Vulnerability

**MITRE CWE:** CWE-77

**References:** https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951 ; BOD 26-04: BOD 26-04: Prioritizing Security Updates Based on Risk | CISA ; Forensics Triage Requirements: BOD 26-04: Implementation Guidance for Prioritizing Security Updates Based on Risk | CISA ;  https://nvd.nist.gov/vuln/detail/CVE-2026-96951

### CVE-2015-5477 - ISC BIND
**Vulnerability:**  ISC BIND Data Processing Errors Vulnerability

**MITRE CWE:** CWE-19

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://web.archive.org/web/20150729014733/https://kb.isc.org/article/AA-01272 ; https://access.redhat.com/errata/RHSA-2015:1513.html; https://supportportal.juniper.net/s/article/2016-01-Security-Bulletin-Junos-Vulnerability-in-ISC-BIND-named-CVE-2015-5477 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2015-5477

### CVE-2016-3081 - Apache Struts
**Vulnerability:** Apache Struts Command Injection Vulnerability

**MITRE CWE:** CWE-77

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://cwiki.apache.org/confluence/display/WW/S2-032 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2016-3081

### CVE-2023-22894 - Strapi Strapi
**Vulnerability:** Strapi Cleartext Storage of Sensitive Information Vulnerability

**MITRE CWE:** CWE-312

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://strapi.io/blog/security-disclosure-of-vulnerabilities-cve ; https://github.com/strapi/strapi/releases ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2023-22894

### CVE-2021-3199 - ONLYOFFICE Docs
**Vulnerability:** ONLYOFFICE Docs Server Path Traversal Vulnerability

**MITRE CWE:** CWE-22

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: ; https://github.com/ONLYOFFICE/DocumentServer/blob/903fe5ab7a275bd69c3c3346af2d21cf87ebeabf/CHANGELOG.md#563 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2021-3199

### CVE-2015-3306 - ProFTPD ProFTPD
**Vulnerability:** ProFTPD Improper Access Control Vulnerability

**MITRE CWE:** CWE-284

**References:** This vulnerability could affect an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: http://www.proftpd.org/ ; https://lists.debian.org/debian-security-announce/2015/msg00154.html ; https://lists.opensuse.org/archives/list/updates@lists.opensuse.org/message/WE6YZRG5UVXMGQ7IVDRYBPIWV4M6UUGM/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2015-3306

### CVE-2026-88779 - Citrix NetScaler
**Vulnerability:** Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability

**MITRE CWE:** CWE-119

**References:** https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174 ; https://community.citrix.com/techzone-blogs/110_security-updates/understanding-and-addressing-cve-2026-88779-in-citrix-netscaler-adc-and-citrix-netscaler-gateway/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-88779

### CVE-2026-102490 - Zammad GmbH Zammad
**Vulnerability:** Zammad GmbH Zammad Improper Privilege Management Vulnerability

**MITRE CWE:** CWE-269

**References:** https://zammad.com/en/product/releases/ ; https://community.zammad.org/t/take-care-local-privilege-escalation-cve-2026-102490-is-reported-as-being-actively-exploited/21297/2 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-102490

### CVE-2026-102489 - Zammad GmbH Zammad
**Vulnerability:** Zammad GmbH Zammad Session Fixation Vulnerability

**MITRE CWE:** CWE-384

**References:** https://zammad.com/en/product/releases/ ; https://community.zammad.org/t/take-care-local-privilege-escalation-cve-2026-102490-is-reported-as-being-actively-exploited/21297/2 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-102489

### CVE-2026-104286 - Fortinet FortiMail
**Vulnerability:** Fortinet FortiMail Path Traversal Vulnerability

**MITRE CWE:** CWE-22, CWE-158

**References:** https://fortiguard.fortinet.com/psirt/FG-IR-26-175 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-104286

### CVE-2026-76504 - Cisco Catalyst SD-WAN Manager
**Vulnerability:** Cisco Catalyst SD-WAN Manager Hex Encoding Vulnerability

**MITRE CWE:** CWE-177

**References:** https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-76504

### CVE-2026-86950 - Apple Multiple Products
**Vulnerability:** Apple Multiple Products Out-of-Bounds Write Vulnerability

**MITRE CWE:** CWE-787

**References:** https://support.apple.com/en-us/149226 ; https://support.apple.com/en-us/149228 ; https://support.apple.com/en-us/149229 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-86950

### CVE-2026-88772 - Citrix NetScaler
**Vulnerability:** Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability

**MITRE CWE:** CWE-119

**References:** Running the provided IOCs in the NetScaler console may help identify indicators of exploitation. Customers must conduct forensic triage as directed by BOD 26‑04 and follow Citrix’s published guidance for mitigations. For more information, please see: https://community.citrix.com/techzone-blogs/110_security-updates/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve-2026-88771-through-cve-2026-88778 ; https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096 ; https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-88772

### CVE-2026-88771 - Citrix NetScaler
**Vulnerability:** Citrix NetScaler Improper Input Validation Vulnerability

**MITRE CWE:** CWE-119

**References:** Running the provided IOCs in the NetScaler console may help identify indicators of exploitation. Customers must conduct forensic triage as directed by BOD 26‑04 and follow Citrix’s published guidance for mitigations. For more information, please see: https://community.citrix.com/techzone-blogs/110_security-updates/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve-2026-88771-through-cve-2026-88778 ; https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096 ; https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-88772

### CVE-2026-67279 - MikroTik RouterOS
**Vulnerability:** Mikrotik RouterOS Improper Enforcement of Behavioral Workflow Vulnerability

**MITRE CWE:** CWE-841

**References:** https://mikrotik.com/supportsec/september-2026-vulnerability ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-67279

### CVE-2026-65660 - Microsoft SharePoint
**Vulnerability:** Microsoft SharePoint Code Injection Vulnerability

**MITRE CWE:** CWE-94

**References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65660 ; ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-65660
