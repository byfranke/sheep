# POST /api/ai/analyze

Analisa um IOC isolado, um CVE ou uma família de malware. Retorna análise narrativa em texto e uma versão estruturada para consumo por automação.

Use este endpoint quando o argumento principal é um IOC e você precisa de saída previsível para parsing programático. Para perguntas em texto livre, use `POST /api/ai/ask`.

## Endpoint

```
POST https://sheep.byfranke.com/api/ai/analyze
```

## Headers obrigatórios

```
X-Sheep-Token: shp_API_KEY_AQUI
Content-Type: application/json
```

## Corpo da requisição

```json
{
  "target": "8.8.8.8",
  "type": "auto",
  "enrich": true,
  "context": null
}
```

| Campo | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `target` | string | sim | Valor do IOC ou artefato. De 1 a 500 caracteres. |
| `type` | string | não | Tipo do artefato. Valores aceitos: `auto`, `ip`, `domain`, `hash`, `url`, `cve`, `malware`. Padrão: `auto`. |
| `enrich` | booleano | não | Quando `true`, a API consulta fontes externas de reputação antes de chamar o modelo. Quando `false`, a análise se baseia apenas no modelo, sem reputação externa. Padrão: `true`. |
| `context` | string ou nulo | não | Contexto adicional opcional em texto livre, até 500 caracteres. Use para passar informação que ajude a interpretar o IOC (origem, alerta correlato, severidade observada). |

O endpoint `/analyze` é padronizado no modelo **Sheep Hunter**. Não há seletor de modelo nesta superfície; todas as chamadas usam o mesmo motor para garantir latência, profundidade e cobrança consistentes. Se você precisa de outros modelos (Scout para triagem rápida, Sage para análise mais profunda), use o endpoint `/api/ai/ask`, onde o seletor é exposto.

### Formatos de resposta

Use o parâmetro de query `?format=` para escolher como o resultado chega ao seu pipeline:

| Valor | Quando usar | Conteúdo |
|---|---|---|
| `markdown` (padrão) | UI humana, Discord bot, e-mail | `AnalysisResult` completo. Inclui `analysis` (markdown narrativo) **e** `structured_analysis` (JSON estruturado). |
| `json` | SIEM, SOAR, n8n, automação | Mesmo `AnalysisResult` SEM o campo `analysis`. Reduz payload em ~60% e evita pós-processamento de Markdown. |
| `stix` | MISP, OpenCTI, TheHive, Cortex, qualquer ferramenta TAXII 2.1 | Resposta substituída por um **STIX 2.1 Bundle** (OASIS). `Content-Type: application/stix+json;version=2.1`. Identity (producer), Indicator (com pattern correto), Vulnerability (para CVE), AttackPattern (MITRE ATT&CK), Relationship e Note. |

Exemplos:

```bash
# Default (compatível com tudo)
curl -X POST "https://sheep.byfranke.com/api/ai/analyze" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# SIEM / n8n — JSON puro, sem o markdown
curl -X POST "https://sheep.byfranke.com/api/ai/analyze?format=json" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# MISP / OpenCTI / TheHive — STIX 2.1 Bundle direto
curl -X POST "https://sheep.byfranke.com/api/ai/analyze?format=stix" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}' > ioc.json
```

Valor inválido para `?format=` retorna `422 Unprocessable Entity`. Em caso de erro de análise (token expirado, quota, IOC inválido), o servidor responde com o shape JSON padrão independentemente do `format` solicitado — STIX Bundle precisa de pelo menos um Indicator/Vulnerability válido para ancorar.

### Tipos suportados

* `auto` faz detecção automática a partir do valor de `target`. Recomendado quando o IOC vem de uma fonte estruturada.
* `ip` para endereços IPv4 ou IPv6.
* `domain` para nomes de domínio.
* `hash` para MD5, SHA-1 e SHA-256. A API resolve o sub-tipo internamente.
* `url` para URLs completas.
* `cve` para identificadores CVE no formato `CVE-AAAA-NNNN[N...]`.
* `malware` para análise de família por nome.

Quando `type` é declarado e contradiz o valor de `target`, a requisição retorna `400 Bad Request`.

## Resposta de sucesso

`HTTP 200 OK`

```json
{
  "success": true,
  "target": "8.8.8.8",
  "type": "ip",
  "analysis": "Endereço atribuído ao serviço público de DNS da Google LLC...",
  "structured_analysis": {
    "verdict": "benign",
    "confidence": 92,
    "summary": "Resolver DNS público amplamente conhecido.",
    "key_findings": [
      "Sem reportes de abuso nos últimos 90 dias.",
      "ASN consistente com o vendor anunciado."
    ],
    "iocs_extracted": [],
    "mitre_techniques": [],
    "recommendations": [
      "Permitir tráfego DNS para este endereço em ambientes corporativos.",
      "Monitorar volume anômalo de queries para detectar tunelamento DNS."
    ],
    "references": []
  },
  "structured": {
    "target": "8.8.8.8",
    "detected_type": "ip",
    "tokens_used": 1598,
    "usage": {
      "prompt_tokens": 312,
      "completion_tokens": 487,
      "total_tokens": 799,
      "estimated": false
    },
    "enrichment_enabled": true,
    "threat_kb_hits": 0,
    "from_cache": false
  },
  "threat_intel": {
    "ioc": "8.8.8.8",
    "type": "ip",
    "risk_score": 5,
    "tags": ["dns", "public-resolver"],
    "enrichment_timestamp": "2026-05-13T18:42:09Z",
    "sources": {
      "virustotal": { "source": "virustotal", "malicious": 0, "suspicious": 0, "harmless": 78 },
      "abuseipdb": { "source": "abuseipdb", "abuse_confidence_score": 0, "total_reports": 0 }
    }
  },
  "model": "sheep",
  "timestamp": "2026-05-13T18:42:11Z",
  "error": null
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `success` | booleano | `true` em respostas bem-sucedidas. |
| `target` | string | Eco do valor enviado em `target`. |
| `type` | string | Tipo resolvido. Pode ser `ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `url`, `cve`, `malware` ou `unknown`. |
| `analysis` | string | Texto narrativo da análise. Pode conter Markdown leve. |
| `structured_analysis` | objeto ou nulo | Versão estruturada para automação. `null` quando o modelo não produziu JSON parseável. |
| `structured` | objeto | Metadados da chamada. Subcampos: `target`, `detected_type`, `tokens_used` (tokens Sheep cobrados da sua quota), `usage` (objeto com `prompt_tokens`, `completion_tokens`, `total_tokens`, `estimated`), `enrichment_enabled`, `threat_kb_hits` (inteiro), `from_cache` (booleano). |
| `threat_intel` | objeto ou nulo | Sumário do enriquecimento aplicado. `null` quando `enrich=false` ou quando o tipo do IOC não suporta enriquecimento. Subcampos: `ioc`, `type`, `risk_score` (0 a 100), `tags`, `enrichment_timestamp`, `sources` (objeto com uma entrada por fonte consultada). |
| `model` | string | Identificador público do serviço. Sempre `sheep`. |
| `timestamp` | string | Data/hora UTC da geração no formato ISO 8601. |
| `error` | string ou nulo | `null` em sucesso. |

O campo `structured.tokens_used` é o valor cobrado da sua quota. Para reconciliação de billing, use sempre `structured.tokens_used`.

O objeto `threat_intel.sources` é populado dinamicamente conforme o tipo do IOC e as fontes que efetivamente responderam. Cada entrada é um objeto com pelo menos o campo `source` e os indicadores específicos daquela fonte. Não há contrato fixo de subcampos por fonte. Use parsing tolerante.

### Estrutura de `structured_analysis`

| Campo | Tipo | Descrição |
|---|---|---|
| `verdict` | string | Um de `benign`, `suspicious`, `malicious`, `inconclusive`. |
| `confidence` | inteiro | Confiança do veredito, faixa 0 a 100. Vereditos `inconclusive` saem sempre com confiança baixa. |
| `summary` | string | Sumário factual em uma ou duas frases, sem Markdown. Adequado para título de ticket. |
| `key_findings` | array de strings | De 3 a 7 observações curtas mais acionáveis. |
| `iocs_extracted` | array de objetos | IOCs secundários inferidos pelo modelo. Cada item tem `type` e `value`. |
| `mitre_techniques` | array de strings | IDs de técnicas e táticas MITRE ATT&CK citadas. |
| `recommendations` | array de strings | Recomendações operacionais defensivas. |
| `references` | array de strings | URLs citadas pela análise. |

## Headers da resposta

Toda resposta inclui headers de rate limit. Consulte `../rate-limits.md`.

## Erros comuns

`400 Bad Request`

* `target` ausente ou fora da faixa de 1 a 500 caracteres.
* `type` fora do conjunto aceito ou contradizendo o valor de `target`.
* `context` acima de 500 caracteres.

`401 Unauthorized`

* Token ausente, mal formado ou desconhecido.

`402 Payment Required`

* `subscription_period_expired`, `subscription_not_active` ou `quota_exceeded`.

`429 Too Many Requests`

* `rate_limit_exceeded`. Mais de 100 requisições por minuto neste endpoint.

Consulte `../errors.md` para detalhamento.

## Exemplo curl

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/analyze" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "CVE-2024-3094",
    "type": "cve"
  }'
```

## Observações de uso

Para IOCs internos sensíveis que não devem ser submetidos a serviços externos de reputação, envie `"enrich": false`. A análise se baseia apenas no conhecimento do modelo, sem consulta upstream.

Quando `structured_analysis` é `null`, o modelo não conseguiu emitir JSON válido. Trate `analysis` como fonte canônica nesse caso. O cliente deve sempre verificar `structured_analysis !== null` antes de fazer parsing.

Análises sobre o mesmo `target` em janela curta podem reusar resultado em cache. A cobrança em tokens Sheep acompanha o consumo original e é debitada normalmente em cada chamada, mesmo quando o conteúdo vem do cache. Esse comportamento mantém a previsibilidade de billing.
