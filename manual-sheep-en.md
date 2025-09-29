# **Sheep Bot Manual**

## Introduction

Welcome to the **Sheep Bot** manual\! This Discord bot is a cybersecurity tool, designed specifically for professionals in **threat intelligence**, **threat hunting**, and **security operations**.

The Sheep Bot offers a comprehensive set of tools that automate security tasks directly within Discord, eliminating the need to switch between multiple platforms and web interfaces.

### Getting Started

To begin using the bot, use these essential commands:

  - **`/about`** - View information about the current version and new features
  - **`/help`** - Display the complete list of available commands
  - **`/version`** - Show version details and changelog

-----

## Security Analysis Tools

### `/vt` Command - VirusTotal Integration

The **`/vt`** command is one of the Sheep Bot's core tools, providing direct access to **VirusTotal** without leaving Discord. VirusTotal uses over 70 antivirus engines for multi-engine analysis of files, URLs, domains, and IP addresses.

#### Supported Functionalities:

**URLs and Domains:**

` /vt [https://example.com](https://example.com)    /vt malicious-domain.com.   `

**File Hashes (MD5, SHA1, SHA256):**

`/vt 13400d5c844b7ab9aacc81822b1e7f02     /vt a1b2c3d4e5f6789012345678901234567890abcd   `

**IP Addresses:**

` /vt 49.89.34.10   `

#### Interpreting the Results

The Sheep Bot presents the results in a structured format:

  - **Threat Level**: General classification (CLEAN, SUSPICIOUS, MALICIOUS DETECTED)
  - **Detection Rate**: Proportion of engines that detected threats (e.g., 19/98 = 19.4%)
  - **Engine Detections**: Detailed list of antiviruses that identified threats
  - **Metadata**: Additional information such as file type, size, timestamps

#### Usage Example with URL:

To check a suspicious URL, such as [https://salat.cn](https://salat.cn) which was reported in the **\#ioc-feed** channel of our threat feed, simply type:

` /vt https://salat.cn   `

### Checking a File with the /vt Command

In addition to URLs, you can also check a file's security. **VirusTotal** uses a unique identifier called a "hash" to analyze and compare files.

#### Extracting Hashes for Analysis

**Windows (PowerShell):**

```powershell
# SHA256 (recommended)
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256

# MD5
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm MD5

# SHA1
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA1
```

**Linux/macOS (Terminal):**

```bash
# SHA256
sha256sum /path/to/file

# MD5
md5sum /path/to/file

# SHA1
sha1sum /path/to/file
```

#### Usage Example with Hash:

In our example, we will use the MD5 hash of a file reported in the **\#ioc-feed**. Simply use the /vt command and the hash you copied:

`/vt 13400d5c844b7ab9aacc81822b1e7f02   `

### Checking an IP Address with the /vt Command

You can also use the **/vt** command to check the reputation of a suspicious IP.

#### Usage Example with IP:

To check the IP `49.89.34.10` which was reported in the **\#ioc-feed**, simply type:

`/vt 49.89.34.10   `

-----

## IP Reputation Analysis with /ipcheck

The **/ipcheck** command uses **AbuseIPDB**, a collaborative database that collects reports of suspicious and malicious IPs from system administrators and security researchers worldwide. It is an excellent tool to check if an IP address has already been reported for malicious activities such as spam, brute-force attacks, port scanning, botnets, among others.

**How to use the /ipcheck command:**
What does it do? It consults the reputation of an IP in the AbuseIPDB database, showing the history of malicious activities.

**Usage Example:**
To check a suspicious IP found in server logs or reported in the **\#ioc-feed**:

`/ipcheck 49.89.34.10   `

The Sheep Bot will return detailed information such as:

  - **Confidence Score**: Confidence percentage regarding the IP's maliciousness
  - **Abuse Reports**: Number of abuse reports
  - **Last Reported**: Date of the last report
  - **Country**: IP's country of origin
  - **ISP**: Internet Service Provider
  - **Usage Type**: Type of use (datacenter, residential, etc.)

-----

## Reconnaissance with Shodan

**Shodan** is known as the "search engine for internet-connected devices." Unlike traditional search engines that index websites, Shodan maps devices and services exposed to the internet, including cameras, routers, servers, industrial systems, and much more.

**Types of searches that can be done with Shodan:**

**By Port:**

  - Search for all devices with a specific port open
  - Example: `port:22` (SSH), `port:80` (HTTP), `port:443` (HTTPS)

**By City:**

  - Locate devices in a specific city
  - Example: `city:"São Paulo"`, `city:"New York"`

**By Company/Organization:**

  - Find devices belonging to a specific organization
  - Example: `org:"Google"`, `org:"Amazon"`

**By IP Address:**

  - Check detailed information for a specific IP
  - History of services, open ports, vulnerabilities

**By Product/Service:**

  - Locate devices running specific software
  - Example: `product:"Apache"`, `product:"nginx"`

### Difference: Shodan vs /portscan

It is important to understand the fundamental difference between **Shodan** queries and the **/portscan** command:

**Shodan (Database):**

  - Uses **previously collected** data through continuous internet scanning
  - Results show the **historical** state of devices
  - May contain outdated information (days, weeks, or months old)
  - Advantage: Fast and does not generate direct traffic to the target
  - Limitation: Information may be outdated

**`/portscan` Command (Real-Time):**

  - Executes a scan **in real-time** at the moment of the query
  - Shows the **current** state of the target's ports
  - Information is always up-to-date
  - Advantage: Accurate and current data
  - Limitation: Generates direct traffic to the target and can be detected

**When to use each one:**

**Use Shodan when:**

  - You want to perform initial reconnaissance without being detected
  - You need historical information about a target
  - You want to map an organization's infrastructure
  - You are performing passive threat intelligence

**Use /portscan when:**

  - You need to confirm the current state of a service
  - You are in an active verification phase
  - You want to validate if a vulnerability still exists
  - You are performing authorized penetration testing

**Usage Example:**

-----

## Cybersecurity Query Assistant

The Sheep Bot includes a **basic chatbot** that can assist with simple cybersecurity questions and some related tasks. It is useful for quick queries when you need basic information or want a second opinion on IOCs.

**What the assistant can do:**

  - Answer basic questions about malware, phishing, IOCs, APTs
  - Provide a simple analysis of suspicious indicators
  - Explain basic cybersecurity concepts
  - Assist with simple threat intelligence tasks

**How to use the /ask command:**

**For basic analysis of IOCs reported in \#ioc-feed:**

**IP Analysis:**

```
/ask analyze this IP 49.89.34.10
```

**Hash Analysis:**

```
/ask analyze this hash 13400d5c844b7ab9aacc81822b1e7f02
```

**URL Analysis:**

```
/ask analyze this URL https://salat.cn
```

**For general questions:**

```
/ask what is APT29?
/ask how to identify phishing attacks?
```

The assistant offers a basic analysis that can complement the technical results from VirusTotal and other specialized tools.

-----

## Professional Security Operations

### Automated Workflows

The Sheep Bot offers **professional workflows** for:

`/workflow incident_response`

  - Automated generation of incident response plans
  - Templates for Malware, Breach, Phishing
  - Severity and escalation management
  - Integration with NIST/SANS methodologies

`/workflow threat_intel`

  - Advanced threat intelligence analysis
  - Multi-source enrichment of IOCs
  - Risk scoring and recommendations
  - Support for IPs, domains, hashes, URLs

`/workflow vulnerability_assessment`

  - Vulnerability assessment
  - Step-by-step methodology
  - Progress tracking
  - Compliance with NIST/SANS frameworks

### Automated Incident Response

`/incident_response` - IR Plan Generation
Creates professional incident response plans based on the type and severity of the threat.

**Supported types:**

  - **Malware**: Analysis and containment of malicious software
  - **Breach**: Response to data breaches
  - **Phishing**: Handling of phishing campaigns
  - **APT**: Response to Advanced Persistent Threats

-----

## Threat Intelligence

### Automated Feeds

The bot automatically monitors **18+ security intelligence sources**, providing:

`/rss_status` - RSS Feeds Status
Checks the status and channels of threat intelligence feeds.

`/ioc_status` - IOCs Status
Monitors the status of Indicators of Compromise feeds.

### Monitored Intelligence Sources:

  - Real-time IOC feeds
  - Threat actor reports
  - Zero-day vulnerabilities
  - Active malware campaigns
  - Threat landscape updates

`#rss-feed #ioc-feed`

-----

## Black Sheep Membership

### Premium Benefits

**Black Sheep members** have access to advanced functionalities:

#### Exclusive Tools:

  - **Full scanning**: Full access to portscan tools
  - **Unlimited usage**: No monthly limits
  - **Priority support**: Priority support
  - **Advanced workflows**: Complete professional workflows

#### How to Check Membership:

` /membership - Check membership status   /redeem <code> - Redeem membership code  `

### Limits for Free Users:

  - **Security commands**: Limited monthly usage
  - **Port scanning**: Restricted access
  - **Workflows**: Basic versions

-----

## Integration with CTI Workflows

### Complete Workflow Example

For **Cyber Threat Intelligence** analysts, a typical workflow would be:

1.  **Suspicious IOC identification**
       `     /vt <hash_or_url_or_ip>     `

2.  **Contextual analysis with the assistant**
       `     /ask analyze this IOC: <details>     `

3.  **Threat intel workflow generation**
       `     /workflow threat_intel     `

4.  **Documentation for incident response**
       `     /incident_response <type> <severity>     `

### Integration with Threat Hunting

For **threat hunters**, the bot offers:

  - Quick analysis of suspicious artifacts
  - Automatic correlation of IOCs
  - Context enrichment via the assistant
  - Structured investigation workflows

-----

# Good Usage Practices

### Operational Security

1.  **IOC Verification**: Always validate suspicious IOCs before proceeding with deeper analysis
2.  **Documentation**: Use workflows to maintain consistent documentation
3.  **Escalation**: Follow the escalation procedures suggested by the workflows
4.  **Correlation**: Combine multiple tools for complete analysis

### Efficiency on Discord

1.  **Dedicated Channels**: Use specific channels for security analyses
2.  **History**: Keep a history of analyses for future reference
3.  **Collaboration**: Share results with the team in a structured manner

-----

## Troubleshooting and Support

### Common Issues

**Rate limiting hit:**

  - Wait for the limit to reset or consider upgrading to Black Sheep

**Analysis error:**

  - Check if the input format is correct (URL, hash, IP)
  - Confirm if the resource is available on VirusTotal

**Commands not working:**

  - Check bot permissions in the channel
  - Confirm if the command was typed correctly

### Contact and Support

  - **Developer**: byFranke
  - **Website**: [https://sheep.byfranke.com/](https://sheep.byfranke.com/)
  - **Discord**: Use the ticket system on the server
  - **Documentation**: `/help` command for quick reference

-----

## Licensing

**License**: Proprietary (Authorized use only)
**Responsible use**: Use the bot ethically and in accordance with the [terms of service](https://byfranke.com/pages/sheep-terms.html)
**Authorized targets**: For legitimate threat analysis only

*This manual covers the main functionalities of the Sheep Bot. For updates and new features, regularly check the `/about` command.*
