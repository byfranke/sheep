# Sheep API

Programmatic access to Sheep 4 cybersecurity features via REST API.

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
4. [Integration Examples](#integration-examples)
5. [Rate Limits](#rate-limits)

---

## Overview

The Sheep API provides RESTful access to Sheep AI capabilities, enabling automation and integration with external tools, SIEM platforms, and custom workflows.

**Base URL:**
```
https://sheep.byfranke.com/api
```

**Requirements:**
- Black Sheep membership
- Valid API token (generate via `/token generate` in Discord)

---

## Authentication

All requests must include the API token in the `X-API-Token` header.

```http
X-API-Token: your-api-token
```

---

## Endpoints

### POST /ai/ask

Query Sheep AI with natural language questions.

**Request:**

```http
POST /api/ai/ask
Content-Type: application/json
X-API-Token: your-api-token

{
  "question": "What is a SQL injection attack?"
}
```

**Response (Success):**

```json
{
  "success": true,
  "response": "SQL injection is a code injection technique..."
}
```

**Response (Error):**

```json
{
  "success": false,
  "error": "Invalid token"
}
```

**Use Cases:**
- Threat intelligence queries
- Incident response guidance
- Malware analysis
- Security best practices

---

## Integration Examples

Ready-to-use scripts are available in the `integrations/` folder.

### CLI Examples

| File | Platform | Requirements |
|------|----------|--------------|
| `cli-examples/sheep-ask` | Linux/macOS | bash, curl, python3 |
| `cli-examples/sheep-ask.ps1` | Windows | PowerShell 5.1+ |
| `cli-examples/sheep-ask.py` | Cross-platform | Python 3.6+ |

**Usage (Bash):**
```bash
./sheep-ask "your-token" "What is a zero-day vulnerability?"
```

**Usage (PowerShell):**
```powershell
.\sheep-ask.ps1 -Token "your-token" -Question "What is a zero-day vulnerability?"
```

**Usage (Python):**
```bash
python3 sheep-ask.py "your-token" "What is a zero-day vulnerability?"
```

### n8n Workflow Examples

| File | Description |
|------|-------------|
| `n8n-examples/sheep_wazuh_analyst_LV15.json` | Wazuh SIEM integration workflow |
| `n8n-examples/sheep-tips.json` | Automated security tips workflow |

Import these JSON files directly into n8n to automate Sheep AI queries.

---

## Rate Limits

API access is subject to the same rate limits as Discord commands. Excessive requests may result in temporary or permanent suspension.

| Tier | Limit |
|------|-------|
| Black Sheep | Standard rate limiting applies |

---

## Support

- **Documentation:** [User Manual](../manual-sheep-en.md)
- **Website:** [sheep.byfranke.com](https://sheep.byfranke.com/)
- **Terms of Service:** [Terms](https://sheep.byfranke.com/pages/terms.html)
