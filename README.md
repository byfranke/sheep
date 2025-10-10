

# Sheep Bot

This document comprehensively covers the features available to users of **Sheep Bot**, including commands, functionalities, usage limits, and practical guidelines for its operation within Discord servers.

## 1. Introduction

Sheep Bot is an automated Discord tool designed for cybersecurity-focused communities, threat intelligence teams, and technical collaboration environments. Its purpose is to provide practical information, automate security-related queries, and streamline administrative management within technical Discord communities.

**Official Bot Access:** [Sheep Bot on Discord](https://discord.com/discovery/applications/1345627921267818517)
**Terms of Service:** [Official Terms of Service](https://byfranke.com/pages/sheep-terms.html#)

---

## 2. Available Functionalities

### 2.1. Threat Monitoring and RSS Notifications

Sheep Bot automatically monitors cybersecurity-related RSS feeds. Upon enabling this function in a specific Discord channel, the bot delivers automated alerts regarding:

* New vulnerabilities (CVEs)
* Cybersecurity incident reports
* Alerts on malicious campaigns
* Security bulletins from sources such as CISA, Microsoft, SecureList, and others

**Activation Command:**

```
/rssfeed
```

*(Restricted to server administrators)*

---

### 2.2. Indicators of Compromise (IoCs) Verification

#### 2.2.1. IP Reputation Check (AbuseIPDB)

Checks the reputation of any public IP address. Provides details including abuse score, recent reports, geographical location, ISP, and blacklist status.

**Command:**

```
/ipcheck <ip>
```

#### 2.2.2. Hash Reputation Check (VirusTotal)

Allows verification of file hashes (MD5, SHA1, SHA256) to determine if they have been flagged as malicious by antivirus engines or other sources on VirusTotal.

**Command:**

```
/vt <hash>
```

#### 2.2.3. URL Analysis (urlscan.io)

Conducts a detailed analysis of suspicious URLs by submitting them to urlscan.io, returning a direct link to the generated analysis report.

**Command:**

```
/urlscan <url>
```

---

### 2.3. Shodan Integration

#### 2.3.1. Host Lookup (Free Tier)

Displays publicly available information about specific hosts, including open ports, service banners, country, ISP, identified vulnerabilities (CVEs), and related data.

**Command:**

```
/shodan <ip>
```

#### 2.3.2. Advanced Filtered Searches (Premium Members Only)

Enables advanced queries in the Shodan database, utilizing filters such as country, ports, services, products, and other advanced parameters.

**Command:**

```
/shodan <query> search
```

---

### 2.4. Port Scanner (Premium Feature)

Executes a rapid TCP port scan using locally installed Nmap, returning a detailed list of open ports.

**Command:**

```
/portscan <ip>
```

* Requires administrators to configure Nmap in the environment hosting Sheep Bot.
* Available exclusively to authorized users (Black Sheep Premium Members).

---

### 2.5. Moderation Commands

The following administrative commands enable direct moderation actions on Discord users:

* Mute a user for 28 days:

```
/mute <user>
```

* Remove mute status:

```
/unmute <user>
```

* Kick a user from the server:

```
/kick <user>
```

* Permanently ban a user:

```
/ban <user>
```

*(Commands restricted to Discord server moderators/administrators.)*

---

### 2.6. Premium Membership and Subscription System

#### 2.6.1. Subscription Activation and Status:

* Activate subscription using a code provided by an administrator:

```
/redeem <code>
```

* Check current subscription status (activation date, plan, expiration):

```
/subscription
```

#### 2.6.2. Premium Membership Benefits (Black Sheep):

* Unlimited usage of advanced commands (`/shodan search`, `/portscan`, and future premium commands).
* No daily or monthly rate limitations applied to commands typically restricted to free users.

---

## 3. Security, Privacy, and Data Governance

* Sheep Bot does not collect private messages or content outside explicitly issued commands.
* Only essential data such as user IDs, commands executed, and command parameters are collected solely for auditing, security monitoring, and usage rate limiting.
* Users may request deletion of their personal data collected by Sheep Bot through formal contact via the [Official Support Form](https://byfranke.com/index-eng.html#Contact).
* All collected data is managed in compliance with LGPD, GDPR, or equivalent data protection regulations.

---

## 4. Limitations and Acceptable Use Policy

* Abuse prevention measures are implemented through rate limiting systems for command usage.
* Repeated abusive or inappropriate attempts result in temporary or permanent blocking of command access for the offending user.
* Illegal activities, automation of attacks, or violations of third-party rights are strictly prohibited and will result in immediate revocation of access to Sheep Bot.

For full details, refer to the [Official Terms of Service](https://byfranke.com/pages/sheep-terms.html#).

---

## 5. Installation and Configuration

Sheep Bot installation is performed directly by the Discord server administrator using the official bot access link:

* [Add Sheep Bot to your Discord Server](https://discord.com/discovery/applications/1345627921267818517)

Once installed, use the `/help` command within Discord to view all available commands directly from your server environment.

---

## 6. Support and Contact

For questions, suggestions, problem reports, or legal inquiries, please use the official support channels:

* [Sheep Community on Discord](https://discord.gg/n8cpR9hJ2y)
* [Official Support Form](https://byfranke.com/index-eng.html#Contact)

---

## 7. Final Remarks

This documentation will be updated periodically as new features are implemented or significant changes occur.

---

## Support My Work 

- **If you appreciate what I do and would like to contribute, any amount is welcome. Your support helps fuel my journey and keeps me motivated to keep creating, learning, and sharing. Thank you for being part of it!**

    [![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)
