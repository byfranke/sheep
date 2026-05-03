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

All requests must include the API token in the `X-Sheep-Token` header.

```http
X-Sheep-Token: your-api-token
```

---

## Endpoints

### POST /ai/ask

Query Sheep AI with natural language questions.

**Request:**

```http
POST /api/ai/ask
Content-Type: application/json
X-Sheep-Token: your-api-token

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

---

## Support

- **Documentation:** [User Manual](../manual-sheep-en.md)
- **Website:** [sheep.byfranke.com](https://sheep.byfranke.com/)
- **Terms of Service:** [Terms](https://sheep.byfranke.com/pages/terms.html)
