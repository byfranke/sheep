# Exemplos em Node.js

Esta página traz exemplos em Node.js para integrar com a Sheep API.

Pré-requisitos:

* Node.js 18 ou superior. A API global `fetch` é usada sem dependências externas.

Substitua `shp_API_KEY_AQUI` pelo seu token. Em produção, leia o valor de uma variável de ambiente ou gerenciador de segredos.

## Cliente mínimo

```javascript
const TOKEN = process.env.SHEEP_API_TOKEN;
const BASE_URL = "https://sheep.byfranke.com";

async function ask(question, model = "auto") {
  const response = await fetch(`${BASE_URL}/api/ai/ask`, {
    method: "POST",
    headers: {
      "X-Sheep-Token": TOKEN,
      "Content-Type": "application/json",
      "User-Agent": "minha-app/1.0",
    },
    body: JSON.stringify({ question, model }),
  });

  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(
      `API ${response.status}: ${detail?.detail?.error ?? "erro"}`
    );
  }

  return response.json();
}

const result = await ask("Resumo do APT29");
console.log(result.response);
console.log(`Tier: ${result.served_by}, custo: ${result.tokens_used} tokens`);
```

## Timeout com AbortController

```javascript
const TOKEN = process.env.SHEEP_API_TOKEN;
const BASE_URL = "https://sheep.byfranke.com";

async function ask(question, options = {}) {
  const { model = "auto", timeoutMs = 45_000 } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${BASE_URL}/api/ai/ask`, {
      method: "POST",
      headers: {
        "X-Sheep-Token": TOKEN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ question, model }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(
        `API ${response.status}: ${detail?.detail?.error ?? "erro"}`
      );
    }

    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}
```

## Retentativa com backoff

```javascript
const MAX_ATTEMPTS = 3;

async function askWithRetry(question, model = "auto") {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const response = await fetch(`${BASE_URL}/api/ai/ask`, {
      method: "POST",
      headers: {
        "X-Sheep-Token": TOKEN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ question, model }),
    });

    if (response.ok) {
      return await response.json();
    }

    if (response.status === 429) {
      const retryAfter = Number(response.headers.get("Retry-After") ?? 10);
      await new Promise((r) => setTimeout(r, retryAfter * 1000));
      continue;
    }

    if (response.status >= 500) {
      await new Promise((r) => setTimeout(r, 2 ** attempt * 1000));
      continue;
    }

    const detail = await response.json().catch(() => ({}));
    throw new Error(
      `API ${response.status}: ${detail?.detail?.error ?? "erro"}`
    );
  }

  throw new Error(`Falha apos ${MAX_ATTEMPTS} tentativas`);
}
```

## Analisar IOC

```javascript
async function analyze(target, type = "auto") {
  const response = await fetch(`${BASE_URL}/api/ai/analyze`, {
    method: "POST",
    headers: {
      "X-Sheep-Token": TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ target, type }),
  });

  if (!response.ok) {
    throw new Error(`API ${response.status}`);
  }

  return response.json();
}

const result = await analyze("CVE-2024-3094", "cve");
console.log(result.structured_analysis?.verdict);
console.log(result.structured.tokens_used);
```

## Verificar saldo

```javascript
async function getProfile() {
  const response = await fetch(`${BASE_URL}/api/profile`, {
    headers: { "X-Sheep-Token": TOKEN },
  });
  if (!response.ok) {
    throw new Error(`API ${response.status}`);
  }
  return response.json();
}

const profile = await getProfile();
console.log(
  `Plano: ${profile.plan.name}, ` +
  `restante: ${profile.usage.tokens_remaining} tokens`
);
```
