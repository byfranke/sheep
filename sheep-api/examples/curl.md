# Exemplos com curl

Esta página traz exemplos prontos com `curl` para os endpoints mais usados da Sheep API.

Substitua `shp_API_KEY_AQUI` pelo seu token. Para emitir um token, consulte `../../getting-started.md`.

## Verificar plano e saldo

```bash
curl -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Este endpoint não consome quota. Use antes de despachar lotes para confirmar saldo.

## Conversação livre

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Liste IOCs típicos associados ao Cobalt Strike.",
    "model": "hunter"
  }'
```

## Análise de IOC

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/analyze" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "CVE-2024-3094",
    "type": "cve"
  }'
```

## Análise sem enriquecimento externo

Use quando o IOC é interno e não deve ser submetido a fontes externas de reputação.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/analyze" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "10.0.0.42",
    "type": "ip",
    "enrich": false
  }'
```

## Listar feeds disponíveis

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Itens mais recentes de um feed

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve/latest?count=20" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Filtrar feed por severidade

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve?limit=10&severity=high" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Health check público

Não exige autenticação.

```bash
curl -X GET "https://sheep.byfranke.com/api/ai/status"
```

## Tratar status e erro em script

O exemplo abaixo separa corpo de status para reagir a falhas em scripts shell.

```bash
TOKEN="shp_API_KEY_AQUI"

RESPONSE=$(curl -sS -w "\n%{http_code}" \
  -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "O que é APT29?"}')

BODY=$(echo "$RESPONSE" | sed '$d')
STATUS=$(echo "$RESPONSE" | tail -n 1)

if [ "$STATUS" -ne 200 ]; then
  echo "Erro $STATUS: $BODY" >&2
  exit 1
fi

echo "$BODY" | jq -r '.response'
```

## Extrair custo da resposta

```bash
curl -sS -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"question": "Resumo de TTPs do APT28"}' \
  | jq '{served_by, tokens_used}'
```

Saída esperada:

```json
{
  "served_by": "hunter",
  "tokens_used": 1842
}
```
