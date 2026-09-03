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

### CVE-2026-59822 - BerriAI LiteLLM
**Vulnerability:** BerriAI LiteLLM Improper Authentication Vulnerability

**MITRE CWE:** CWE-287, CWE-306

**References:** https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-59822

### CVE-2026-48710 - Kludex Starlette
**Vulnerability:** Kludex Starlette HTTP Request/Response Smuggling Vulnerability

**MITRE CWE:** CWE-444

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-48710

### CVE-2026-49869 - Kestra Kestra OSS
**Vulnerability:** Kestra OSS OS Command Injection Vulnerability

**MITRE CWE:** CWE-78, CWE-184, CWE-287, CWE-918

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-49869

### CVE-2026-82329 - JFrog Artifactory
**Vulnerability:** JFrog Artifactory Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://docs.jfrog.com/releases/docs/jfrog-security-advisories ; https://docs.jfrog.com/releases/docs/artifactory-self-managed-releases ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-82329

### CVE-2026-9586 - Sangoma Switchvox
**Vulnerability:** Sangoma Switchvox SQL Injection Vulnerability

**MITRE CWE:** CWE-89

**References:** https://sangomakb.atlassian.net/wiki/spaces/Switchvox/pages/1802371073/Switchvox+-+Release+Notes+Version+8.4.0.2+July+14+2026 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-9586

### CVE-2026-83548 - SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability

**MITRE CWE:** CWE-918, CWE-441

**References:** https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-83548

### CVE-2026-83549 - SonicWall SMA1000 Appliances
**Vulnerability:** SonicWall SMA1000 Appliances OS Command Injection Vulnerability

**MITRE CWE:** CWE-78

**References:** https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0016 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-83549

### CVE-2026-82078 - PaperCut NG/MF
**Vulnerability:** PaperCut NG/MF Unsafe Reflection Vulnerability

**MITRE CWE:** CWE-470

**References:** https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/?lid=2oneu2wt0ct4 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-82078

### CVE-2026-81578 - PaperCut NG/MF
**Vulnerability:** PaperCut NG/MF Missing Authentication for Critical Function Vulnerability

**MITRE CWE:** CWE-306

**References:** https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-81578

### CVE-2023-49105 - ownCloud ownCloud
**Vulnerability:** ownCloud Improper Authentication Vulnerability

**MITRE CWE:** CWE-287

**References:** https://owncloud.org/security ; https://owncloud.com/security-advisories/webdav-api-authentication-bypass-using-pre-signed-urls/ ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2023-49105

### CVE-2026-53362 - Linux Kernel
**Vulnerability:** Linux Kernel Unspecified Vulnerability

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: ; https://git.kernel.org/stable/c/14200d435af9a9eeb444f529fc2f689a236b7962; https://git.kernel.org/stable/c/65fb14cbebb0cd0eff903a22d33537ddc8b95769; https://git.kernel.org/stable/c/46f201f8b4c39633a1fa3dc12459f506d470993d; https://git.kernel.org/stable/c/6374fb9edf72c67a118a2c214a0dddd04c921e0a; https://git.kernel.org/stable/c/e9eacf19281ea2498b36291b56c9606118c2d74e; https://git.kernel.org/stable/c/736b380e28d0480c7bc3e022f1950f31fe53a7c5 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-53362

### CVE-2026-66384 - JFrog Artifactory
**Vulnerability:** JFrog Artifactory Improper Limitation of a Pathname to a Restricted Directory Vulnerability

**MITRE CWE:** CWE-22

**References:** https://docs.jfrog.com/releases/docs/jfrog-security-advisories ; https://docs.jfrog.com/releases/docs/artifactory-self-managed-releases ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-66384

### CVE-2021-23758 - Ajax.NET Professional Ajax.NET Professional
**Vulnerability:** Ajax.NET Professional Deserialization of Untrusted Data Vulnerability

**MITRE CWE:** CWE-502

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/michaelschwarz/Ajax.NET-Professional/commit/b0e63be5f0bb20dfce507cb8a1a9568f6e73de57 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2021-23758

### CVE-2015-3246 - Red Hat Libuser
**Vulnerability:** Red Hat Libuser Race Condition Vulnerability

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://access.redhat.com/articles/1537873 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2015-3246

### CVE-2015-5287 - Red Hat Automatic Bug Reporting Tool
**Vulnerability:** Red Hat Automatic Bug Reporting Tool Privilege Escalation Vulnerability

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://github.com/abrt/abrt/commit/3c1b60cfa62d39e5fff5a53a5bc53dae189e740e ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2015-5287

### CVE-2022-0995 - Linux Kernel
**Vulnerability:** Linux Kernel Out-of-Bounds Write Vulnerability

**MITRE CWE:** CWE-787

**References:** This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that could be used by different products. For more information, please see: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=93ce93587d36493f2f86921fa79921b3cba63fbb ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2022-0995

### CVE-2026-8452 - Citrix NetScaler ADC and NetScaler Gateway
**Vulnerability:** Citrix NetScaler ADC and NetScaler Gateway Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability

**MITRE CWE:** CWE-119

**References:** https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696604 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-8452

### CVE-2019-1068 - Microsoft SQL Server
**Vulnerability:** Microsoft SQL Server Remote Code Execution Vulnerability

**References:** https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1068 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2019-1068

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
