# Exemplos em Python

Esta página traz exemplos prontos em Python para integrar com a Sheep API.

Pré-requisitos:

* Python 3.10 ou superior.
* Biblioteca `requests`. Instale com `pip install requests`.

Substitua `shp_API_KEY_AQUI` pelo seu token. Em produção, leia o valor de uma variável de ambiente ou gerenciador de segredos.

## Cliente mínimo

```python
import os
import requests

TOKEN = os.environ["SHEEP_API_TOKEN"]
BASE_URL = "https://sheep.byfranke.com"

def ask(question: str, model: str = "auto") -> dict:
    response = requests.post(
        f"{BASE_URL}/api/ai/ask",
        json={"question": question, "model": model},
        headers={
            "X-Sheep-Token": TOKEN,
            "Content-Type": "application/json",
            "User-Agent": "minha-app/1.0",
        },
        timeout=45,
    )
    response.raise_for_status()
    return response.json()

result = ask("Quais técnicas MITRE são associadas ao APT29?")
print(result["response"])
print(f"Tier: {result['served_by']}, custo: {result['tokens_used']} tokens")
```

## Tratar erro estruturado

A API retorna detalhes em `detail.error` e `detail.message`. O exemplo abaixo distingue erros transitórios de erros permanentes.

```python
import os
import time
import requests

TOKEN = os.environ["SHEEP_API_TOKEN"]
BASE_URL = "https://sheep.byfranke.com"
MAX_ATTEMPTS = 3

def ask(question: str, model: str = "auto") -> dict:
    payload = {"question": question, "model": model}
    headers = {"X-Sheep-Token": TOKEN, "Content-Type": "application/json"}

    for attempt in range(MAX_ATTEMPTS):
        response = requests.post(
            f"{BASE_URL}/api/ai/ask", json=payload,
            headers=headers, timeout=45,
        )

        if response.status_code == 200:
            return response.json()

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "10"))
            time.sleep(retry_after)
            continue

        if 500 <= response.status_code < 600:
            time.sleep(2 ** attempt)
            continue

        try:
            detail = response.json().get("detail", {})
        except ValueError:
            detail = {}
        raise RuntimeError(
            f"API error {response.status_code}: "
            f"{detail.get('error')} - {detail.get('message')}"
        )

    raise RuntimeError(f"Falha após {MAX_ATTEMPTS} tentativas")
```

## Verificar saldo antes de despachar lote

```python
import os
import requests

TOKEN = os.environ["SHEEP_API_TOKEN"]
BASE_URL = "https://sheep.byfranke.com"

def get_profile() -> dict:
    response = requests.get(
        f"{BASE_URL}/api/profile",
        headers={"X-Sheep-Token": TOKEN},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()

profile = get_profile()
remaining = profile["usage"]["tokens_remaining"]
status = profile["subscription"]["status"]

if status != "active":
    raise SystemExit(f"Assinatura nao esta ativa: {status}")

ESTIMATIVA_POR_CHAMADA = 3000  # tokens Sheep
CHAMADAS_PLANEJADAS = 50

if remaining < ESTIMATIVA_POR_CHAMADA * CHAMADAS_PLANEJADAS:
    raise SystemExit(
        f"Saldo insuficiente: {remaining} tokens restantes."
    )

print(f"Saldo OK: {remaining} tokens disponiveis.")
```

## Analisar uma lista de IOCs

```python
import os
import requests

TOKEN = os.environ["SHEEP_API_TOKEN"]
BASE_URL = "https://sheep.byfranke.com"

def analyze(target: str, ioc_type: str = "auto") -> dict:
    response = requests.post(
        f"{BASE_URL}/api/ai/analyze",
        json={"target": target, "type": ioc_type},
        headers={
            "X-Sheep-Token": TOKEN,
            "Content-Type": "application/json",
        },
        timeout=45,
    )
    response.raise_for_status()
    return response.json()

iocs = [
    ("CVE-2024-3094", "cve"),
    ("malicious.example.com", "domain"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),
]

for target, ioc_type in iocs:
    result = analyze(target, ioc_type)
    if not result["success"]:
        print(f"{target}: falha - {result.get('error')}")
        continue

    structured = result.get("structured_analysis") or {}
    print(
        f"{target} -> "
        f"verdict: {structured.get('verdict')}, "
        f"confianca: {structured.get('confidence')}, "
        f"custo: {result['structured']['tokens_used']} tokens"
    )
```

## Consumir feed

```python
import os
import requests

TOKEN = os.environ["SHEEP_API_TOKEN"]
BASE_URL = "https://sheep.byfranke.com"

def latest(feed_id: str, count: int = 10) -> list:
    response = requests.get(
        f"{BASE_URL}/api/feeds/{feed_id}/latest",
        params={"count": count},
        headers={"X-Sheep-Token": TOKEN},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["items"]

for item in latest("cve", count=20):
    print(item.get("title"))
```

## Boas práticas em código

Configure `User-Agent` identificável. Facilita diagnóstico em suporte.

Use `timeout` em toda chamada. Sugerido: 45 segundos para `/ask` e `/analyze`, 15 segundos para os demais.

Leia o token de variável de ambiente ou gerenciador de segredos. Não use literal no código.

Adicione redaction de logs para qualquer string que comece com `shp_`. Frameworks de log como `structlog` e `loguru` aceitam processadores customizados.
