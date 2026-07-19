# Threat Intel Digest

## SonicWall SMA1000 Zero-Day Vulnerabilities: Full Technical Details (risk score: 10/10)
Source: https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/

**Summary:** SonicWall has identified two actively exploited vulnerabilities in its SMA1000 Secure Mobile Access appliance, including a server-side request forgery flaw and a post-authentication code injection issue. Both vulnerabilities have been confirmed to be in use by threat actors and carry high CVSS scores, indicating significant risk.

**Why high-risk:** These vulnerabilities are confirmed to be actively exploited in the wild and pose a direct risk to organizations using the affected appliances. The high CVSS scores and lack of workarounds make them highly critical.

**ATT&CK Technique:** T1089 - System Network Connections Discovery (UNVERIFIED)
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for command execution and request manipulation, which can be detected through network connection logs.
**Recommendation:** New use case - Implement new rules to monitor for unusual network connections and command executions.

## New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code (risk score: 10/10)
Source: https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html

**Summary:** An unauthenticated HTTP request can execute arbitrary code on any WordPress site running version 6.9 or 7.0 due to a flaw in the core codebase, making even sites with no plugins vulnerable.

**Why high-risk:** This describes a high-risk security vulnerability as it allows unauthenticated attackers to run arbitrary code on WordPress sites, which could lead to data theft, site compromise, or other malicious activities.

**ATT&CK Technique:** T1089 - Web Shell (UNVERIFIED)
**Log Sources:** Web server access logs, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows unauthenticated attackers to execute code, making it highly feasible for an attacker to exploit.
**Recommendation:** New use case - A new detection rule is needed to identify potential web shell activity on affected WordPress sites.

## Microsoft July 2026 Patch Tuesday: Record 622 Vulnerabilities with Two Active Zero-Days (risk score: 9/10)
Source: https://thehackernews.com/2026/07/microsoft-patches-record-622-flaws.html

**Summary:** Microsoft released a record 622 patches in July 2026, with two vulnerabilities currently being actively exploited. These include an unauthenticated remote code execution flaw in SharePoint Server and a BitLocker bypass requiring physical access.

**Why high-risk:** This describes actual security threats with active exploitation, making it a high-risk situation.

**ATT&CK Technique:** T1136 - Create Account
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows unauthenticated attackers to escalate privileges, which can be detected through security event logs and endpoint monitoring.
**Recommendation:** Tune existing rule - Existing rules can be tuned to detect unusual network activity indicative of privilege escalation attempts.

## Microsoft's July 2026 Patch Tuesday: 570 Vulnerabilities and 3 Zero-Days (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/microsoft/microsoft-july-2026-patch-tuesday-fixes-massive-570-flaws-3-zero-days/

**Summary:** Microsoft released July 2026 Patch Tuesday updates addressing 570 vulnerabilities, including three zero-days. Two of these zero-days were actively exploited: CVE-2026-56155 affects Active Directory Federation Services, and CVE-2026-56164 impacts Microsoft SharePoint Server. Another notable issue is CVE-2026-50661, a publicly disclosed Windows BitLocker bypass.

**Why high-risk:** This passage describes a significant number of vulnerabilities, including zero-days that were exploited in the wild. These issues pose a high risk to organizations using affected Microsoft products.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - Remote code execution vulnerabilities are highly feasible to detect through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules can be tuned to specifically look for signs of remote code execution attempts based on the patterns of these vulnerabilities.

## ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files (risk score: 8/10)
Source: https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html

**Summary:** ACR Stealer, an infostealer active since 2024, has been used to steal browser credentials, session tokens, and Microsoft 365 files through pasting a command into a Run box and executing it.

**Why high-risk:** This describes a specific infostealer threat that has been actively used to steal sensitive information. The risk is significant as it involves the theft of credentials and corporate data.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The attack vector involves pasting a command into the Run box, which can be detected in security event logs and EDR/endpoint logs.
**Recommendation:** Tune existing rule - Existing rules for detecting obfuscated commands can be tuned to catch this specific behavior.

## Fake Coding Tests Deliver OtterCookie-Aligned Malware Hidden in SVG Flag Images (risk score: 8/10)
Source: https://thehackernews.com/2026/07/north-korea-linked-hackers-hide.html

**Summary:** North Korean threat actors are using steganography in SVG images within fake coding tests to deliver a multi-stage malware payload called OTTERCOOKIE, which includes tools for stealing browser credentials, crypto wallets, and files.

**Why high-risk:** This describes a specific cybersecurity threat involving a sophisticated attack technique and a known malware payload. The risk is high due to the active use of this method by advanced threat actors.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Web server access logs, EDR/endpoint logs
**Detection Feasibility:** Medium - Detection is possible but requires specific knowledge of the steganographic technique used.
**Recommendation:** Tune existing rule - Existing rules can be tuned to look for anomalies in SVG files or unusual network traffic patterns associated with steganography.

## HollowByte DDoS flaw bloats OpenSSL server memory with 11-byte payload (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/

**Summary:** A vulnerability called HollowByte enables unauthenticated attackers to cause a denial-of-service condition on OpenSSL servers using a 11-byte payload.

**Why high-risk:** This describes a specific security vulnerability that can lead to a DoS condition, which is a high-risk issue for affected OpenSSL servers.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, Web server access logs, Firewall/VPN logs
**Detection Feasibility:** High - The attack can be detected through network traffic and security event logs.
**Recommendation:** Tune existing rule - Existing DoS detection rules can be fine-tuned to identify and mitigate this specific attack vector.

## Inc Ransomware Exploits SonicWall SMA Zero-Days (risk score: 8/10)
Source: https://www.darkreading.com/vulnerabilities-threats/inc-ransomware-exploits-sonicwall-sma-zero-days

**Summary:** Two vulnerabilities in SonicWall's mobile access appliances can be exploited when chained together to grant threat actors root-level access.

**Why high-risk:** This describes a specific security vulnerability that could be exploited to gain unauthorized access to SonicWall devices, which poses a significant risk.

**ATT&CK Technique:** T1548 - Abuse Elevation Control Mechanism
**Log Sources:** Windows Security Event Log, Firewall/VPN logs
**Detection Feasibility:** High - The vulnerabilities allow for gaining root-level capabilities, which can be detected through security event logs and firewall activity.
**Recommendation:** New use case - This is a new exploit targeting specific vulnerabilities, requiring a new detection mechanism.

## Microsoft warns of surge in ACR Stealer attacks on customers (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/

**Summary:** Microsoft has noticed an increase in attacks where the ACR Stealer malware is used to steal browser-stored passwords, authentication tokens, and sensitive documents from its enterprise customers.

**Why high-risk:** This describes a current cybersecurity threat involving malware that targets enterprise customers, posing a direct risk to their data security.

**ATT&CK Technique:** T1110 - Brute Force
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The attack targets browser-stored credentials and can be detected through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules for credential dumping can be tuned to detect ACR Stealer activity based on known indicators of compromise.

## New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Tokens (risk score: 8/10)
Source: https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html

**Summary:** The NadMesh botnet was observed in early July targeting exposed AI services, including image generators and workflow builders, by harvesting AWS keys through a Shodan harvester.

**Why high-risk:** This describes an ongoing security threat where a botnet is actively targeting exposed AI services for credential theft, which poses a significant risk to organizations using these services.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Cloud audit logs, EDR/endpoint logs
**Detection Feasibility:** High - The botnet is actively scanning and attempting to exploit exposed AI services, which can be detected through cloud audit logs and endpoint security logs.
**Recommendation:** Tune existing rule - Existing security controls should be tuned to detect and respond to brute force attempts on exposed AI services.

## New Windows LegacyHive zero-day gives hackers admin privileges (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/

**Summary:** A security researcher has discovered a Windows zero-day exploit called LegacyHive that enables privilege escalation on current Windows systems.

**Why high-risk:** This describes a specific cybersecurity threat as it involves a zero-day exploit that can be used to gain administrative privileges, which is a high-risk scenario.

**ATT&CK Technique:** T1548 - Abuse Elevation Control Mechanism
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The exploit allows privilege escalation, which is a common attack vector and can be detected through security event logs and endpoint detection and response tools.
**Recommendation:** Tune existing rule - Existing rules for privilege escalation can be tuned to detect this specific exploit based on the behavior described.

## Seven Malicious Vite npm Packages Use Blockchain C2 to Deliver a RAT (risk score: 8/10)
Source: https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html

**Summary:** Cybersecurity researchers have identified seven malicious npm packages targeting the Vite frontend tooling ecosystem, using a blockchain-based command-and-control infrastructure known as ChainVeil.

**Why high-risk:** This describes a confirmed security threat involving malicious npm packages and a sophisticated C2 infrastructure, posing a risk to users of the Vite ecosystem.

**ATT&CK Technique:** T1071 - Application Layer Protocol
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The use of a blockchain-based C2 infrastructure indicates the attackers are leveraging command execution techniques, which can be detected through endpoint security and Windows security logs.
**Recommendation:** Tune existing rule - Existing EDR rules can be tuned to detect unusual outbound network traffic patterns associated with blockchain-based C2 communications.

## Update now: 7-Zip fixes RCE flaw exploitable with malicious archives (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/

**Summary:** 7-Zip version 26.02 was released to address a remote code execution vulnerability that could be exploited through specially crafted compressed files.

**Why high-risk:** This describes a specific security vulnerability and its fix, which poses a direct risk to users of 7-Zip if they do not update to the latest version.

**ATT&CK Technique:** T1190 - Exploit Public-Facing Application
**Log Sources:** Windows Security Event Log, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability can be exploited through specially crafted compressed files, which can be detected by monitoring security event logs and endpoint activity.
**Recommendation:** New use case - Implementing a new detection rule to monitor for suspicious file openings and network activities associated with 7-Zip usage.

## WordPress Core "wp2shell" RCE flaws get public exploits, patch now (risk score: 8/10)
Source: https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/

**Summary:** Public exploits have been released for critical 'wp2shell' remote code execution vulnerabilities in WordPress Core, urging immediate patching by administrators.

**Why high-risk:** This describes a confirmed security threat with public exploits available, making it a high-risk situation for WordPress users.

**ATT&CK Technique:** T1059 - Command and Scripting Interpreter
**Log Sources:** Windows Security Event Log, Web server access logs, EDR/endpoint logs
**Detection Feasibility:** High - The vulnerability allows remote code execution, which can be detected through security event logs and endpoint logs.
**Recommendation:** Tune existing rule - Existing security solutions can likely detect malicious activities related to command execution based on known indicators of compromise.

## 1M+ Emails Use Hidden Text to Dupe AI Security Filters (risk score: 5/10)
Source: https://www.darkreading.com/threat-intelligence/1m-emails-hidden-text-dupe-ai-security-filters

**Summary:** The document discusses how artificial intelligence and language models may struggle to detect phishing emails that use text salting, which involves hiding malicious content within seemingly harmless text, thus bypassing security filters.

**Why high-risk:** This describes a potential security issue where AI-based security filters might fail to identify phishing emails due to the use of text salting techniques. However, it does not describe an active threat or attack in progress but rather a vulnerability that could be exploited.

## Abbott probes two cyber incidents amid extortion claims (risk score: 5/10)
Source: https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/

**Summary:** Abbott Laboratories is investigating two cybersecurity incidents: unauthorized access to internal systems used in its Cancer Diagnostics business and a claim that attackers breached its LabCentral portal, potentially stealing company data.

**Why high-risk:** These incidents involve unauthorized access and potential data theft, which are serious cybersecurity issues but have not been confirmed as actual breaches or attacks in the wild.

## OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests (risk score: 5/10)
Source: https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html

**Summary:** An unpatched OpenSSL server may allocate up to 131 KB of memory for a 11-byte TLS request that never arrives, potentially leading to a denial-of-service condition. The issue was reported by Okta’s Red Team and is known as the HollowByte flaw.

**Why high-risk:** This describes a potential denial-of-service vulnerability that can freeze server memory, but there is no evidence of active exploitation or widespread impact. The risk is moderate due to the need for specific conditions to trigger the issue.

## Forgotten Bootloaders Expose Secure Boot Blind Spot (risk score: 4/10)
Source: https://www.darkreading.com/cyber-risk/forgotten-bootloaders-expose-secure-boot-blind-spot

**Summary:** Nearly a dozen revoked UEFI shim bootloaders were trusted for years, allowing attackers to bypass Secure Boot mechanisms.

**Why high-risk:** This describes a past security issue where revoked bootloaders were trusted, enabling attackers to bypass Secure Boot. However, it does not indicate if this is currently active or widespread, nor does it detail any ongoing threat.

## Identity Attacks Overtake Exploits as Top Ransomware Cause (risk score: 4/10)
Source: https://www.darkreading.com/identity-access-management-security/identity-attacks-overtake-exploits-top-ransomware-cause

**Summary:** Email attacks became the leading cause of ransomware infections last year, despite 97% of credential-based attacks using multifactor authentication, which still resulted in compromises.

**Why high-risk:** This passage describes a change in the methods used for ransomware infections and the effectiveness of certain security measures. While it highlights a shift in tactics, it does not describe an ongoing or imminent threat but rather past trends.

## Inside the Search for "Clean" Residential Proxies for Carding (risk score: 3/10)
Source: https://www.bleepingcomputer.com/news/security/inside-the-search-for-clean-residential-proxies-for-carding/

**Summary:** The document discusses how cybercriminals are moving away from traditional residential proxies due to their ineffectiveness against modern fraud detection systems and are instead opting for 'clean' residential proxies combined with additional identity signals like browser fingerprints and device profiles.

**Why high-risk:** This passage describes a trend in cybercriminal tactics but does not detail an active threat or vulnerability. It focuses on the evolution of methods used by criminals to evade detection, which while concerning, is not an immediate or direct security risk.

## Best Practices for Sourdough Starter Maintenance in Home Kitchens (risk score: 1/10)
Source: https://example.com/baking/sourdough-starter-guide

**Summary:** The passages provide guidance on maintaining a sourdough starter, including feeding schedules, temperature control, and signs of a healthy starter. Issues such as hooch formation and failure to rise are discussed.

**Why high-risk:** These passages do not describe any actual cybersecurity threat, vulnerability, or attack in progress. They are focused on baking techniques and do not relate to security.

## Agentic AI: Taming the Unpredictable (risk score: 1/10)
Source: https://www.darkreading.com/cybersecurity-operations/agentic-ai-untamable-ask-the-right-security-questions

**Summary:** The document suggests that agentic artificial intelligence poses significant risks to organizations, prompting them to reconsider their security strategies.

**Why high-risk:** While the passage indicates potential risks associated with agentic AI, it does not provide specific details about a current cybersecurity threat, vulnerability, or attack. The risk is speculative and based on the potential impact of AI on organizational security.

## Armenia Detains Russian Tourist on U.S. Warrant for REvil Hacker, Lawyers Say Wrong Man (risk score: 1/10)
Source: https://thehackernews.com/2026/07/armenia-detains-russian-tourist-on-us.html

**Summary:** Armenia has detained a Russian tourist named Aleksandr Ermakov at the request of the U.S., who is suspected of being a REvil ransomware hacker.

**Why high-risk:** This passage describes a legal and law enforcement action related to a suspected cybercriminal but does not detail an ongoing cybersecurity threat, vulnerability, or attack.

## E.U. Orders Google to Open Android Mic, Camera and Screen to Rival AI Assistants (risk score: 1/10)
Source: https://thehackernews.com/2026/07/eu-orders-google-to-open-android-mic.html

**Summary:** The European Commission has mandated that Google provide rivals of its AI assistant with the same access to Android devices as Google's own assistant, including camera, microphone, screen, and background app control.

**Why high-risk:** This is not a cybersecurity threat but rather a regulatory mandate affecting device access permissions. It does not describe a current security issue or vulnerability.

## Ernst & Young discloses data breach after support system hack (risk score: 1/10)
Source: https://www.bleepingcomputer.com/news/security/ernst-and-young-discloses-data-breach-after-support-system-hack/

**Summary:** Ernst & Young is informing its customers about a data breach resulting from the compromise of a third-party support ticket system utilized by its IT staff.

**Why high-risk:** This passage describes a data breach incident but does not detail any ongoing cybersecurity threat or vulnerability. It is a notification of past events rather than an active or imminent risk.

## Gold Eagle Clearinghouse Targets Security Gap, but How Is Unclear (risk score: 1/10)
Source: https://www.darkreading.com/vulnerabilities-threats/gold-eagle-clearinghouse-targets-security-gap

**Summary:** The White House initiated a program called Gold Eagle to coordinate responses to vulnerabilities in the emerging AI landscape, though many uncertainties remain regarding its implementation.

**Why high-risk:** This passage describes a government initiative aimed at coordinating responses to potential vulnerabilities in AI technology. It does not describe an actual cybersecurity threat, vulnerability, or attack in progress.

## GoldenEyeDog Subgroup Linked to DigiCert Breach and Code-Signing Certificate Theft (risk score: 1/10)
Source: https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html

**Summary:** The April 2026 DigiCert security incident was attributed to a threat activity cluster called CylindricalCanine, which is a subgroup of the GoldenEyeDog cybercrime group.

**Why high-risk:** This passage describes a specific cybersecurity incident but does not detail an ongoing threat or vulnerability. It provides attribution for a past event.

## Google Bets 'Agentic Defense' Strategy Can Outpace Attackers (risk score: 1/10)
Source: https://www.darkreading.com/cloud-security/google-bets-agentic-defense-strategy-outpace-attackers

**Summary:** Google Cloud integrates Wiz capabilities into its agentic defense platform to automate threat detection and remediation specifically targeting AI attacks.

**Why high-risk:** This passage describes a defensive strategy and does not detail an actual cybersecurity threat, vulnerability, or attack in progress.

## Guten Tag, Bonjour, Hola to Our European Cyber Defenders! (risk score: 1/10)
Source: https://www.darkreading.com/threat-intelligence/guten-tag-bonjour-hola-european-cyber-defenders

**Summary:** The passage announces the launch of Dark Reading's DR Global section, which provides region-specific cybersecurity intelligence outside of North America.

**Why high-risk:** This passage does not describe an actual cybersecurity threat, vulnerability, or attack in progress. It is promotional content for a new section of a cybersecurity publication.

## Police Disrupt a €140M Cyber Fraud Ring in Spain (risk score: 1/10)
Source: https://www.darkreading.com/threat-intelligence/police-disrupt-140m-euro-cyber-fraud-ring-spain

**Summary:** Iberian hackers conducted various cyberattacks and used complex financial networks to launder the proceeds.

**Why high-risk:** This passage describes past cybercriminal activities but does not indicate an ongoing or immediate threat. It is historical information about a disrupted fraud ring.

## The Future of Age Verification: Your Face Never Leaves Your Device (risk score: 1/10)
Source: https://www.bleepingcomputer.com/news/security/the-future-of-age-verification-your-face-never-leaves-your-device/

**Summary:** The document discusses a method for on-device age estimation that does not transmit or store facial images, aiming to reduce biometric privacy risks while helping organizations comply with age verification laws.

**Why high-risk:** This passage describes a technical solution for age verification that focuses on privacy and compliance. It does not describe an actual cybersecurity threat, vulnerability, or attack in progress.

## The Race to Field Military Autonomy Is On, Can Trusted Information Infrastructure Keep Pace? (risk score: 1/10)
Source: https://thehackernews.com/2026/07/the-race-to-field-military-autonomy-is.html

**Summary:** Military forces are accelerating the development and deployment of autonomous capabilities, driven by new investments and faster acquisition processes. The focus now is on ensuring the trustworthiness of these systems as they are rapidly integrated into operations.

**Why high-risk:** While the passage discusses the rapid development of autonomous military technologies, it does not describe an actual cybersecurity threat, vulnerability, or attack in progress. It is focused on the broader context of military modernization and trustworthiness.

## The Real AI Threat Is Blind Trust (risk score: 1/10)
Source: https://www.darkreading.com/application-security/real-ai-threat-blind-trust

**Summary:** The passage discusses the potential risks associated with AI models that both interpret and execute commands without human oversight, which could lead to cybersecurity issues.

**Why high-risk:** While the passage highlights a concern about AI models lacking oversight, it does not describe an actual cybersecurity threat, vulnerability, or attack in progress. It is more about a potential risk rather than an immediate security issue.

## Windows Server 2022 reach end of mainstream support in 90 days (risk score: 1/10)
Source: https://www.bleepingcomputer.com/news/microsoft/windows-server-2022-reach-end-of-mainstream-support-in-90-days/

**Summary:** Microsoft has announced that Windows Server 2022 will reach its mainstream support end date in October 2026, after which it will enter extended support and continue receiving security updates for five additional years.

**Why high-risk:** This announcement does not describe an actual cybersecurity threat, vulnerability, or ongoing attack. It is a standard lifecycle event for a software product.
