# User Manual - Sheep v3.7.1

## Table of Contents

1.  **[Introduction](#1-introduction)**
    * 1.1 System Overview
    * 1.2 Hybrid Architecture (v3.7.1)
2.  **[Artificial Intelligence Assistant (/ask)](#2-artificial-intelligence-assistant-ask)**
3.  **[Cyber Threat Intelligence (CTI)](#3-cyber-threat-intelligence-cti)**
    * 3.1 Advanced Analysis (`/threat_intel`)
    * 3.2 Indicator Validation (`/ioc_check`)
    * 3.3 URL Analysis (`/urlscan`)
    * 3.4 VirusTotal Integration (`/virustotal`)
    * 3.5 IP Reputation (`/ipcheck`)
4.  **[Monitoring & Intelligence Feeds](#4-monitoring--intelligence-feeds)**
    * 4.1 Data Sources (RSS & OTX)
    * 4.2 Channel Configuration (`/rssfeed`, `/iocfeed`)
    * 4.3 System Status
5.  **[Reconnaissance & Scanning](#5-reconnaissance--scanning)**
    * 5.1 Host Intelligence (`/shodan`)
    * 5.2 Port Scanning (`/portscan`)
6.  **[Operations & Workflows](#6-operations--workflows)**
    * 6.1 Standardized Workflows
    * 6.2 Incident Response
7.  **[Server Administration (Staff)](#7-server-administration-staff)**
8.  **[Licensing (Black Sheep)](#8-licensing-black-sheep)**

---

## 1. Introduction

### 1.1 System Overview
**Sheep Bot** is an advanced cybersecurity assistant for Discord, designed to provide threat intelligence, security analysis, and CTI operations automation. Developed for security professionals, SOC analysts, and *threat hunters*, the system centralizes queries to multiple security APIs into a single interface.

### 1.2 Hybrid Architecture (v3.7.1)
The "Sheep Threat Analyst" build operates on a hybrid model:
* **AI Integration:** Llama 3 and Mistral models for contextual processing of questions and analyses.
* **Machine Learning:** Automatic fallback to traditional classification algorithms.
* **Feedback Mechanism:** Visual processing indicators for complex analyses (45s timeout).

---

## 2. Artificial Intelligence Assistant (`/ask`)

The core module of version 3.7.1. The `/ask` command utilizes an ML engine with continuous learning to answer technical questions and analyze threats with context.

**Features:**
* Automatic extraction and analysis of IoCs within the prompt.
* Explanation of security concepts (APTs, TTPs, Malware families).
* Contextual queries (e.g., "What is the relationship between this hash and the Lazarus Group?").

**Syntax:**
```text
/ask <question_or_instruction>
````

*Example:* `/ask analyze this hash 13400d5c844b7ab9aacc81822b1e7f02`

-----

## 3\. Cyber Threat Intelligence (CTI)

This section details the priority analysis tools for data enrichment and investigation.

### 3.1 Advanced Analysis (`/threat_intel`)

Sheep Bot's most robust analysis tool. It performs IoC enrichment by cross-referencing multiple intelligence sources simultaneously.

**Capabilities:**

  * "Multi-source" enrichment with risk scoring.
  * Support for IPs, Domains, Hashes, and URLs.
  * Generation of professional recommendations and next steps.

**Syntax:**

```text
/threat_intel <ioc>
```

*Example:* `/threat_intel malicious-domain.com`

### 3.2 Indicator Validation (`/ioc_check`)

Agile tool for quick reputation verification of an indicator. Ideal for initial triage before a deep analysis.

**Syntax:**

```text
/ioc_check <ioc>
```

### 3.3 URL Analysis (`/urlscan`)

Integration with the **URLScan.io** API. Performs a security scan on the target URL, identifying phishing behaviors or malicious scripts without the user needing to access the link.

**Syntax:**

```text
/urlscan <url>
```

### 3.4 VirusTotal Integration (`/virustotal`)

Direct query to the VirusTotal database for file and URL analysis against over 70 antivirus engines.

**Syntax:**

```text
/virustotal <hash/url/ip>
```

### 3.5 IP Reputation (`/ipcheck`)

Verifies IP address reputation based on **AbuseIPDB**, returning a history of reports (Brute Force, SSH Abuse, etc.).

**Syntax:**

```text
/ipcheck <ip>
```

-----

## 4\. Monitoring & Intelligence Feeds

Sheep Bot acts as a real-time aggregator of news and indicators.

### 4.1 Data Sources

The system continuously monitors:

  * **RSS Feeds (15 Sources):** Aggregation from portals such as *The Hacker News, Bleeping Computer, Krebs on Security, CISA Alerts*.
  * **IOC Feeds (AlienVault OTX):** Monitoring of 4 main categories:
      * Malware & Botnets
      * Phishing Campaigns
      * C2 Servers (Command & Control)
      * Ransomware Indicators

### 4.2 Channel Configuration

To receive automatic updates on your server, use the configuration commands below. Administrator permissions are required.

  * **`/rssfeed`**: Configures the current channel to receive cybersecurity news.
  * **`/iocfeed`**: Configures the current channel to receive alerts for new Indicators of Compromise.

### 4.3 System Status

  * **`/rss_status`**: Checks the connectivity status of news feeds.
  * **`/ioc_status`**: Checks the status of threat feeds.

-----

## 5\. Reconnaissance & Scanning

### 5.1 Host Intelligence (`/shodan`)

Queries the Shodan database for *passive reconnaissance*. Identifies exposed services, vulnerabilities, and banner information.

**Syntax:**

```text
/shodan <query>
```

### 5.2 Port Scanning (`/portscan`)

Active real-time port scanner (Nmap + Python).
*Note: Exclusive use for Black Sheep members (Full Access) or limited in the free version.*

**Syntax:**

```text
/portscan <target> [ports]
```

-----

## 6\. Operations & Workflows

### 6.1 Standardized Workflows (`/workflow`)

Generates procedure templates based on industry frameworks (NIST/SANS) to guide the analyst.

**Types:**

  * `incident_response`
  * `threat_hunting`
  * `vulnerability_assessment`

**Syntax:**

```text
/workflow <type>
```

### 6.2 Incident Response (`/incident_response`)

Generates automated action plans based on the severity and type of incident (Malware, Breach, Phishing, APT). Includes escalation and timeline management.

**Syntax:**

```text
/incident_response <type> <severity>
```

*Example:* `/incident_response breach critical`

-----

## 7\. Server Administration (Staff)

Utility commands for bot moderation and configuration on the server. Requires *Staff* or *Administrator* permissions.

  * **`/config`**: General bot configuration panel.
  * **`/clear <amount>`**: Mass remove messages from the channel (Bulk Delete).
  * **`/kick <user> [reason]`**: Kicks a user from the server.
  * **`/ban <user> [reason]`**: Bans a user from the server.

-----

## 8\. Licensing (Black Sheep)

The "Black Sheep Membership" system offers premium access and removal of limits.

**Benefits:**

  * Smart/expanded rate limiting.
  * Full access to `/portscan`.
  * Unlimited tools (monthly).

**Commands:**

  * **`/membership`**: Checks subscription status.
  * **`/redeem <code>`**: Redeems a Black Sheep activation code.

-----

**Legal Notice:** The developer is not responsible for the misuse of scanning tools. All analyses must be performed on authorized targets.
