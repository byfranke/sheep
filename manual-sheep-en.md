# User Manual - Sheep 4

## Table of Contents

1.  **[Introduction](#1-introduction)**
    * 1.1 System Overview
    * 1.2 Architecture and Features
2.  **[Sheep AI](#2-sheep-ai)**
    * 2.1 Ask Anything (/ask)
    * 2.2 Incident Response (/incident_response)
3.  **[Professional Workflows](#3-professional-workflows)**
    * 3.1 Workflow Automation (/workflow)
4.  **[Security Tools](#4-security-tools)**
    * 4.1 Multi-Source Analysis (/analyze)
    * 4.2 VirusTotal Integration (/virustotal)
    * 4.3 IP Reputation (/ipcheck)
    * 4.4 IP Abuse Reporting (/ipreport)
5.  **[Reconnaissance Tools](#5-reconnaissance-tools)**
    * 5.1 Host Intelligence (/shodan)
    * 5.2 Port Scanning (/portscan)
    * 5.3 URL Analysis (/urlscan)
6.  **[Monitoring and Intelligence Feeds](#6-monitoring-and-intelligence-feeds)**
    * 6.1 RSS Cybersecurity News (/rssfeed)
    * 6.2 IOC Threat Feeds (/iocfeed)
7.  **[Membership System](#7-membership-system)**
    * 7.1 Free Tier Limits
    * 7.2 Black Sheep Membership
    * 7.3 Free Trial (/trial)
    * 7.4 Code Redemption (/redeem)
    * 7.5 Membership Status (/membership)
8.  **[Server Administration](#8-server-administration)**
    * 8.1 Moderation Commands
    * 8.2 Welcome System (/welcome)
    * 8.3 Auto-Role Configuration (/autorole)
9.  **[Utility Commands](#9-utility-commands)**
    * 9.1 Help (/help)
    * 9.2 About (/about)
    * 9.3 Version (/version)
    * 9.4 Language (/language)
10. **[API Access](#10-api-access)**
    * 10.1 Token Management (/token)
11. **[Usage Policies](#11-usage-policies)**
    * 3.1 Multi-Source Analysis (/analyze)
    * 3.2 IP Reputation (/ipcheck)
    * 3.3 IP Abuse Reporting (/ipreport)
    * 3.4 VirusTotal Integration (/virustotal)
    * 3.5 URL Analysis (/urlscan)
4.  **[Reconnaissance and Scanning](#4-reconnaissance-and-scanning)**
    * 4.1 Host Intelligence (/shodan)
    * 4.2 Port Scanning (/portscan)
5.  **[Monitoring and Intelligence Feeds](#5-monitoring-and-intelligence-feeds)**
    * 5.1 RSS Cybersecurity News (/rssfeed)
    * 5.2 IOC Threat Feeds (/iocfeed)
6.  **[Membership System](#6-membership-system)**
    * 6.1 Free Tier Limits
    * 6.2 Black Sheep Membership
    * 6.3 Free Trial (/trial)
    * 6.4 Code Redemption (/redeem)
    * 6.5 Membership Status (/membership)
7.  **[Server Administration](#7-server-administration)**
    * 7.1 Moderation Commands
    * 7.2 Welcome System (/welcome)
    * 7.3 Auto-Role Configuration (/autorole)
8.  **[Utility Commands](#8-utility-commands)**
    * 8.1 Help (/help)
    * 8.2 About (/about)
    * 8.3 Version (/version)
    * 8.4 Language (/language)
9.  **[API Access](#9-api-access)**
    * 9.1 Token Management (/token)
10. **[Usage Policies](#10-usage-policies)**

---

## 1. Introduction

### 1.1 System Overview

Sheep 4 is an advanced cybersecurity assistant for Discord, designed for threat intelligence, security analysis, and CTI operations automation. Developed for security professionals, SOC analysts, and threat hunters, the system centralizes queries to multiple security APIs into a unified interface.

**Official Access:** [Sheep Bot on Discord](https://discord.com/discovery/applications/1345627921267818517)

**Terms of Service:** [Official Terms of Service](https://byfranke.com/pages/sheep-terms.html)

### 1.2 Architecture and Features

Sheep 4 operates with an advanced hybrid model:

* **AI Integration:** Sheep AI - proprietary artificial intelligence engine for contextual analysis.
* **Machine Learning:** Automatic fallback system with pattern recognition and learning capabilities.
* **Multi-API Integration:** Unified access to VirusTotal, AbuseIPDB, Shodan, URLScan.io, and AlienVault OTX.
* **Real-time Monitoring:** Continuous threat intelligence feed aggregation.

---

## 2. Sheep AI

Commands powered by Sheep AI for advanced cybersecurity automation and intelligence.

### 2.1 Ask Anything (/ask)

Integration with Sheep AI for natural language queries, cybersecurity advice, and incident response support.

**Capabilities:**

* General cybersecurity questions
* Threat intelligence queries
* Incident response guidance
* Security best practices
* Vulnerability analysis
* Malware investigation

**Syntax:**

```
/ask <question>
```

**Examples:**

* `/ask What is a SQL injection attack?`
* `/ask Analyze this hash 13400d5c844b7ab9aacc81822b1e7f02`
* `/ask Explain the MITRE ATT&CK framework`

### 2.2 Incident Response (/incident_response)

Integration with Sheep AI for guided incident response, including step-by-step instructions and best practices.

**Capabilities:**

* Guided incident response
* Step-by-step instructions
* Playbook recommendations
* Threat containment advice
* Forensics and evidence collection

**Key Features:**

* **AI-Generated Plans:** Uses Sheep AI to generate contextual, professional response plans.
* **Bilingual Support:** Automatically responds in your preferred language (English or Portuguese).
* **Unique Incident ID:** Each response includes a traceable incident ID (e.g., `IR-20251205-A1B2C3D4`).
* **Quick Reference:** Includes relevant tools, frameworks, and resources for each incident type.

**Incident Types:**

| Type | Description | Focus Areas |
|------|-------------|-------------|
| `malware` | Malware infection detected | Malware family ID, infection vector, C2 detection, memory forensics |
| `breach` | Data breach with exfiltration | Data classification, regulatory notification (GDPR/LGPD), legal coordination |
| `phishing` | Phishing campaign targeting users | Campaign scope, credential compromise, URL/attachment analysis |
| `ddos` | Distributed Denial of Service | Attack type classification, CDN/ISP coordination, traffic scrubbing |
| `insider` | Insider threat detection | User activity timeline, evidence preservation, HR/Legal coordination |
| `ransomware` | Ransomware attack | Immediate isolation, variant identification, backup verification, DO NOT PAY guidance |
| `apt` | Advanced Persistent Threat | Dwell time estimation, persistence mechanisms, MITRE ATT&CK mapping |

**Severity Levels:**

| Level | Label | Response Priority |
|-------|-------|-------------------|
| `critical` | CRITICAL | Executive escalation required. All hands on deck. Business continuity at risk. |
| `high` | HIGH | Senior management notification. Significant business impact expected. |
| `medium` | MEDIUM | Standard incident response procedures. Monitor for escalation. |
| `low` | LOW | Document and monitor. Investigation required but no immediate threat. |

**Syntax:**

```
/incident_response <incident_type> <severity>
```

**Examples:**

```
/incident_response ransomware critical
/incident_response insider high
/incident_response phishing medium
/incident_response malware low
```

---

## 3. Professional Workflows

Procedures based on industry frameworks (NIST/SANS). This section does not use AI.

### 3.1 Workflow Automation (/workflow)

Generates standardized procedure templates based on industry frameworks (NIST/SANS) to guide analysts through security operations. This command is static and does not use AI.

**Available Workflow Types:**

* `incident_response` - Incident handling procedures
* `threat_hunting` - Proactive threat detection
* `vulnerability_assessment` - Security assessment procedures
* `malware_analysis` - Malware investigation steps
* `forensics` - Digital forensics procedures

**Syntax:**

```
/workflow <type>
```

**Example:** `/workflow threat_hunting`

---

## 4. Security Tools

Tools for IOC analysis and reputation, integrated with multiple security APIs.

### 4.1 Multi-Source Analysis (/analyze)

Comprehensive IOC enrichment tool that cross-references multiple intelligence sources simultaneously for thorough threat analysis.

**Capabilities:**

* Multi-source enrichment with risk scoring.
* Support for IPs, domains, hashes, and URLs.
* Professional recommendations and suggested next steps.
* Automatic threat classification.

**Syntax:**

```
/analyze <ioc>
```

**Examples:**

* `/analyze 192.168.1.1`
* `/analyze malicious-domain.com`
* `/analyze 44d88612fea8a8f36de82e1278abb02f`

### 4.2 IP Reputation (/ipcheck)

Verifies IP address reputation using AbuseIPDB, returning abuse confidence score, report history, and geographic information.

**Information Provided:**

* Abuse confidence score (0-100%)
* Number of reports
* Geographic location (Country, ISP)
* Report categories (Brute Force, SSH Abuse, DDoS, etc.)
* Whitelisted status

**Syntax:**

```
/ipcheck <ip>
```

**Example:** `/ipcheck 8.8.8.8`

### 4.3 IP Abuse Reporting (/ipreport)

Report abusive IP addresses to AbuseIPDB to contribute to the global threat intelligence community.

**Report Categories:**

* DNS Compromise
* DNS Poisoning
* Fraud Orders
* DDoS Attack
* FTP Brute-Force
* Port Scan
* Phishing
* Spam
* SSH Brute-Force
* VPN IP
* Web Spam
* Hacking
* SQL Injection
* Spoofing
* Brute-Force
* Bad Web Bot
* Exploited Host
* Web App Attack
* IoT Targeted

**Syntax:**

```
/ipreport <ip> <categories> <comment>
```

**Example:** `/ipreport 192.168.1.100 ssh_brute_force,port_scan Detected multiple failed SSH attempts`

### 4.4 VirusTotal Integration (/virustotal)

Direct query to the VirusTotal database for comprehensive file, URL, and IP analysis against 70+ antivirus engines.

**Supported Input Types:**

* File hashes (MD5, SHA1, SHA256)
* URLs
* IP addresses
* Domains

**Syntax:**

```
/virustotal <hash/url/ip/domain>
```

**Examples:**

* `/virustotal 44d88612fea8a8f36de82e1278abb02f`
* `/virustotal https://suspicious-site.com`

---

## 5. Reconnaissance Tools

Tools for passive reconnaissance, port scanning and URL analysis.

### 5.1 Host Intelligence (/shodan)

Queries the Shodan database for passive reconnaissance, identifying exposed services, vulnerabilities, and infrastructure information.

**Information Provided:**

* Open ports and services
* Operating system detection
* Known vulnerabilities (CVEs)
* SSL/TLS certificate details
* Geographic location
* ISP and organization
* Historical data

**Syntax:**

```
/shodan <ip_or_query>
```

**Examples:**

* `/shodan 8.8.8.8`
* `/shodan apache country:US`

### 5.2 Port Scanning (/portscan)

Active real-time port scanning using Shodan on-demand scanning capabilities.

**Note:** This feature is exclusive to Black Sheep Premium members.

**Syntax:**

```
/portscan <target>
```

**Example:** `/portscan 192.168.1.1`

### 5.3 URL Analysis (/urlscan)

Integration with URLScan.io for comprehensive website security analysis, identifying phishing behaviors, malicious scripts, and suspicious content.

**Analysis Includes:**

* Screenshot capture
* DOM analysis
* Network requests
* Certificate information
* Malicious indicators
* Technologies detected

**Syntax:**

```
/urlscan <url>
```

**Example:** `/urlscan https://example.com`

---

## 6. Monitoring and Intelligence Feeds

### 6.1 RSS Cybersecurity News (/rssfeed)

Configures automatic cybersecurity news delivery to a designated channel. The system aggregates content from multiple trusted sources.

**Available Sources:**

* The Hacker News
* Bleeping Computer
* Krebs on Security
* CISA Alerts
* Dark Reading
* SecurityWeek
* Threatpost
* And additional sources

**Actions:**

* `enable` - Activate feed in current channel
* `disable` - Deactivate feed
* `status` - Check current configuration

**Syntax:**

```
/rssfeed <action>
```

**Note:** Requires Administrator permissions.

### 6.2 IOC Threat Feeds (/iocfeed)

Configures automatic Indicators of Compromise delivery from AlienVault OTX to a designated channel.

**IOC Categories:**

* Malware and Botnets
* Phishing Campaigns
* Command and Control (C2) Servers
* Ransomware Indicators
* Exploit Kits
* APT Indicators

**Actions:**

* `enable` - Activate feed in current channel
* `disable` - Deactivate feed
* `status` - Check current configuration

**Syntax:**

```
/iocfeed <action>
```

**Note:** Requires Administrator permissions.

---

## 7. Membership System

### 7.1 Free Tier Limits

Free users have monthly limits on security commands to ensure fair usage:

| Command | Monthly Limit |
|---------|---------------|
| /analyze | 10 uses |
| /ask | 10 uses |
| /ipcheck | 10 uses |
| /ipreport | 10 uses |
| /portscan | 10 uses |
| /shodan | 10 uses |
| /urlscan | 10 uses |
| /virustotal | 10 uses |
| /workflow | 10 uses |

Limits reset on the first day of each month.

### 7.2 Black Sheep Membership

Premium membership removes all usage limits and provides access to exclusive features.

**Benefits:**

* Unlimited usage of all security commands
* Exclusive access to /portscan
* API Token for integration with other byFranke services
* Priority support
* Special Discord role in the Sheep Community
* Access to exclusive member channels

**Available Plans:**

For updated pricing, please visit the official store: [sheep.byfranke.com/store](https://sheep.byfranke.com/store)

| Plan | Duration |
|------|----------|
| Trial | 3 days (free, one-time) |
| 3 Months | 90 days |
| 6 Months | 180 days |
| 12 Months | 365 days |

### 7.3 Free Trial (/trial)

Request a free 3-day trial of Black Sheep membership to experience premium features.

**Limitations:**

* One trial per Discord account
* One trial per email address
* Trial code valid for 30 days after generation

**Syntax:**

```
/trial <email>
```

**Example:** `/trial user@example.com`

The trial code will be sent to the provided email address.

### 7.4 Code Redemption (/redeem)

Activate a Black Sheep membership using a redemption code.

**Code Format:** `SB3M-XXXX-XXXX-XXXX` or `SB6M-XXXX-XXXX-XXXX` or `SB12-XXXX-XXXX-XXXX`

**Syntax:**

```
/redeem <code>
```

**Example:** `/redeem SB3M-A1B2-C3D4-E5F6`

### 7.5 Membership Status (/membership)

Check your current membership status, including plan details, expiration date, and usage statistics.

**Syntax:**

```
/membership
```

---

## 8. Server Administration

### 8.1 Moderation Commands

Standard moderation commands for server management. Requires appropriate permissions.

**Ban User:**

```
/ban <user> [reason]
```

**Kick User:**

```
/kick <user> [reason]
```

**Timeout User:**

```
/mute <user> [duration] [reason]
```

**Remove Timeout:**

```
/unmute <user>
```

### 8.2 Welcome System (/welcome)

Configure automatic welcome messages for new server members.

**Actions:**

* `enable` - Activate welcome messages in current channel
* `disable` - Deactivate welcome messages
* `status` - Check current configuration

**Syntax:**

```
/welcome <action>
```

**Note:** Requires Administrator permissions.

### 8.3 Auto-Role Configuration (/autorole)

Configure automatic role assignment for new members.

**Actions:**

* `set` - Set a role to be automatically assigned
* `remove` - Remove auto-role configuration
* `status` - Check current configuration

**Syntax:**

```
/autorole <action> [role]
```

**Note:** Requires Administrator permissions.

---

## 9. Utility Commands

### 9.1 Help (/help)

Display available commands based on your permission level and membership status.

**Syntax:**

```
/help
```

### 9.2 About (/about)

Display information about Sheep 4, including version, features, and developer information.

**Syntax:**

```
/about
```

### 9.3 Version (/version)

Display current bot version and recent changelog information.

**Syntax:**

```
/version
```

### 9.4 Language (/language)

Change your preferred language for bot responses.

**Supported Languages:**

* English (en)
* Portuguese (pt)
* Spanish (es)

**Syntax:**

```
/language <code>
```

**Example:** `/language pt`

---

## 10. API Access

### 10.1 Token Management (/token)

Manage your personal API token for programmatic access to Sheep 4 features.

**Actions:**

* `generate` - Generate a new API token
* `revoke` - Revoke current token
* `status` - Check token status

**Syntax:**

```
/token <action>
```

**Note:** Requires Black Sheep membership for API access.

---

## 11. Usage Policies

### Acceptable Use

* All scanning and analysis must be performed on authorized targets only.
* Do not use the bot for illegal activities or unauthorized access attempts.
* Respect rate limits and do not attempt to circumvent usage restrictions. **Violations are subject to permanent ban.**
* Report any bugs or vulnerabilities through official channels.

### Data Privacy

* Sheep 4 does not collect private messages or content outside explicitly issued commands.
* Only essential data (user IDs, commands executed, command parameters) is collected for auditing, security monitoring, and rate limiting.
* Users may request deletion of their personal data through the official support channels.
* All collected data is managed in compliance with LGPD, GDPR, and equivalent data protection regulations.

### Legal Notice

The developer is not responsible for the misuse of scanning and analysis tools. Users are solely responsible for ensuring they have proper authorization before performing any security assessments.

For complete terms, refer to the [Official Terms of Service](https://byfranke.com/pages/sheep-terms.html).

---

## Support and Contact

For questions, suggestions, problem reports, or legal inquiries:

* **Discord Community:** [Sheep Community](https://discord.gg/n8cpR9hJ2y)
* **Support Form:** [Official Contact](https://byfranke.com/index-eng.html#Contact)

---

**Document Version:** 4.0.0

**Last Updated:** December 2025
