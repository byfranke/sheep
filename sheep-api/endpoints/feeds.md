# Feeds de Threat Intelligence

A Sheep API expõe um conjunto de feeds curados de Threat Intelligence. Cada feed reúne itens publicados por fontes selecionadas e expõe uma janela rolante de aproximadamente 30 dias. Use os feeds para alimentar SIEMs, dashboards internos, playbooks de SOAR e workflows de automação.

Operações disponíveis:

* `GET /api/feeds/` lista todos os feeds disponíveis.
* `GET /api/feeds/categories` lista as categorias e os feeds em cada uma.
* `GET /api/feeds/{feed_id}` retorna itens de um feed específico com filtros e paginação.
* `GET /api/feeds/{feed_id}/latest` retorna os itens mais recentes de um feed.
* `GET /api/feeds/{feed_id}/stats` retorna estatísticas agregadas do feed.
* `GET /api/feeds/all/summary` retorna um resumo consolidado de todos os feeds.

**Custo.** Os feeds NÃO consomem tokens Sheep. As rotas de feeds não têm rate-limit dedicado e respeitam apenas o limite global de 120 requisições por minuto por IP aplicado a toda a Sheep API.

## Headers obrigatórios

Todas as operações de feeds exigem o header de autenticação.

```
X-Sheep-Token: shp_API_KEY_AQUI
```

## Catálogo de feeds

Cada feed tem um identificador estável usado em `{feed_id}`. Use sempre o `feed_id`, nunca o nome de exibição, nas chamadas de API.

| feed_id | Nome | Categoria | Conteúdo |
|---|---|---|---|
| `cve` | CVE Monitor | `vulnerabilities` | Vulnerabilidades críticas publicadas pelo NVD (NIST). |
| `ransomware` | Ransomware Monitor | `ransomware` | Vítimas de ransomware publicadas em leak sites. |
| `threat_intel` | Threat Intel Monitor | `threat_intelligence` | Relatórios APT e análises de malware de fornecedores de segurança. |
| `apt_infrastructure` | APT Infrastructure Monitor | `infrastructure` | Servidores C2 e infraestrutura maliciosa identificada pela comunidade. |
| `data_leak` | Data Leak Monitor | `data_breach` | Vazamentos e breaches corporativos. |
| `ics_scada` | ICS/SCADA Monitor | `ics` | Vulnerabilidades em sistemas de controle industrial. |
| `kaspersky` | Kaspersky Monitor | `threat_intelligence` | Alertas e pesquisas publicados pelo SecureList. |
| `financial_intel` | Financial Intel Monitor | `financial_intel` | CTI financeira: sanções OFAC SDN, ações de enforcement, takedowns de mixers e pesquisa on-chain. |
| `ioc_stream` | IOC Stream | `iocs` | Stream em tempo quase real de IPs, URLs e hashes maliciosos. |
| `rss_news` | Security News | `news` | Notícias agregadas de cibersegurança de fontes RSS de fornecedores e research. |

Para descobrir a lista oficial em runtime, use `GET /api/feeds/`.

## GET /api/feeds/

Lista todos os feeds disponíveis com metadados básicos. Use no boot do seu cliente para descobrir o catálogo antes de filtrar.

Resposta de sucesso:

```json
{
  "feeds": [
    {
      "id": "cve",
      "name": "CVE Monitor",
      "description": "Critical vulnerabilities from NVD (NIST)",
      "category": "vulnerabilities",
      "update_interval": 60,
      "last_updated": "2026-05-13T18:00:00Z",
      "item_count": 412
    }
  ],
  "total": 10
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `feeds[].id` | string | Identificador estável do feed. Use este valor em `{feed_id}`. |
| `feeds[].name` | string | Nome de exibição. |
| `feeds[].description` | string | Resumo de uma linha do que o feed agrega. |
| `feeds[].category` | string | Categoria lógica. |
| `feeds[].update_interval` | inteiro | Intervalo nominal de atualização em segundos. |
| `feeds[].last_updated` | string ou nulo | Data/hora ISO 8601 UTC da última indexação. `null` quando o feed ainda não recebeu nenhum item. |
| `feeds[].item_count` | inteiro | Número de itens disponíveis na janela atual. |
| `total` | inteiro | Tamanho da lista. |

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/categories

Lista as categorias e os feeds em cada categoria. Útil para construir agrupamentos em dashboards.

Resposta de sucesso:

```json
{
  "categories": {
    "vulnerabilities": ["cve"],
    "ransomware": ["ransomware"],
    "threat_intelligence": ["threat_intel", "kaspersky"],
    "infrastructure": ["apt_infrastructure"],
    "data_breach": ["data_leak"],
    "ics": ["ics_scada"],
    "financial_intel": ["financial_intel"],
    "iocs": ["ioc_stream"],
    "news": ["rss_news"]
  },
  "total": 9
}
```

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/categories" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/{feed_id}

Retorna itens de um feed específico, com filtros opcionais e paginação. Endpoint principal para alimentação de SIEM e dashboards.

### Parâmetros de query

| Parâmetro | Tipo | Padrão | Faixa | Descrição |
|---|---|---|---|---|
| `limit` | inteiro | 50 | 1 a 500 | Máximo de itens a retornar. |
| `offset` | inteiro | 0 | ≥ 0 | Deslocamento para paginação. |
| `since` | string ISO 8601 | — | — | Filtra para itens com `timestamp` posterior à data informada. |
| `severity` | string | — | — | Filtra por severidade. Casa parcial case-insensitive contra o campo `severity` do item (`high`, `medium`, `low`, etc.). |
| `category` | string | — | — | Filtra pelo campo `category` do item. Casa parcial case-insensitive. |

`feed_id` desconhecido retorna `404 Not Found` com a lista de identificadores válidos.

### Resposta de sucesso

```json
{
  "feed_id": "cve",
  "feed_name": "CVE Monitor",
  "category": "vulnerabilities",
  "items": [
    {
      "id": "CVE-2026-12345",
      "title": "Pre-authentication RCE in Example Webserver",
      "url": "https://example.org/advisory/CVE-2026-12345",
      "published_at": "2026-05-13T09:14:22Z",
      "severity": "high",
      "tags": ["rce", "critical"]
    }
  ],
  "count": 1,
  "last_updated": "2026-05-13T18:00:00Z",
  "next_update": "2026-05-13T18:01:00Z"
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `feed_id` | string | Eco do identificador do feed consultado. |
| `feed_name` | string | Nome de exibição do feed. |
| `category` | string | Categoria lógica do feed. |
| `items` | array de objetos | Itens publicados que casam com os filtros. Campos detalhados na seção abaixo. |
| `count` | inteiro | Tamanho de `items` após aplicar filtros e paginação. |
| `last_updated` | string ou nulo | Data/hora ISO 8601 UTC da última indexação do feed. |
| `next_update` | string ou nulo | Estimativa de quando a próxima atualização chega. Calculada a partir de `last_updated + update_interval`. |

### Estrutura de cada item

Cada feed publica o objeto bruto recebido da fonte upstream em `items`. A maior parte dos feeds expõe ao menos:

| Campo | Tipo | Presença | Descrição |
|---|---|---|---|
| `id` | string | sempre | Identificador único do item dentro do feed (CVE ID, hash do leak post, etc.). |
| `title` | string | quase sempre | Título humano. |
| `url` | string | quase sempre | URL para a fonte original (advisory, leak post, relatório). |
| `published_at` ou `timestamp` | string ISO 8601 | quase sempre | Data/hora de publicação na fonte. |
| `severity` | string | depende do feed | `high`, `medium`, `low`, ou rótulo equivalente da fonte. |
| `tags` | array | depende do feed | Etiquetas livres aplicadas pela fonte. |

Campos adicionais específicos da fonte podem aparecer:

* `cve` traz `cvss`, `vector`, `affected`, `cwe`.
* `ransomware` traz `actor`, `victim`, `country`, `sector`.
* `apt_infrastructure` traz `ioc_type`, `ioc_value`, `malware_family`.
* `ioc_stream` traz `ioc_type`, `ioc_value`, `confidence`.
* `financial_intel` traz `category` (`SANCTION`, `RANSOM-PAY`, `MIXER`, `EXCHANGE`, `ENFORCEMENT`, `ADVISORY`, `ANALYSIS`), `source_name`, e `wallets` (lista de endereços BTC, ETH e TRX detectados no conteúdo da fonte, quando aplicável).

Para parsing programático, trate `items` como dicionários abertos: verifique a presença de cada campo antes de usar.

### Exemplos por feed

CVE mais severas dos últimos sete dias.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve?severity=high&since=2026-05-06T00:00:00Z&limit=50" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Vítimas de ransomware nas últimas 24 horas.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/ransomware?since=2026-05-12T00:00:00Z" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Infraestrutura APT, paginada em blocos de 200.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/apt_infrastructure?limit=200&offset=0" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"

curl -X GET "https://sheep.byfranke.com/api/feeds/apt_infrastructure?limit=200&offset=200" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Stream de IOC para alimentar bloqueio em firewall.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/ioc_stream?limit=500" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Alertas ICS/SCADA da semana.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/ics_scada?since=2026-05-06T00:00:00Z" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Notícias agregadas para boletim interno.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/rss_news?limit=20" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Sinais financeiros e enforcement das últimas 24 horas.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/financial_intel?since=2026-05-20T00:00:00Z" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/{feed_id}/latest

Atalho para o caso de uso mais comum: pegar os N itens mais recentes sem precisar paginar manualmente.

### Parâmetros de query

| Parâmetro | Tipo | Padrão | Faixa | Descrição |
|---|---|---|---|---|
| `count` | inteiro | 10 | 1 a 100 | Número de itens a retornar. |

### Resposta de sucesso

```json
{
  "feed_id": "cve",
  "items": [],
  "count": 10,
  "last_updated": "2026-05-13T18:00:00Z"
}
```

### Exemplos

Últimas 20 vítimas de ransomware.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/ransomware/latest?count=20" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Últimos 5 CVEs publicados.

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve/latest?count=5" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/{feed_id}/stats

Retorna estatísticas agregadas do feed. Útil para painéis de saúde e detecção de regressão.

### Resposta de sucesso

```json
{
  "feed_id": "cve",
  "total_items": 412,
  "items_today": 18,
  "items_this_week": 89,
  "last_updated": "2026-05-13T18:00:00Z",
  "categories": {
    "rce": 42,
    "info-disclosure": 7
  },
  "sources": {
    "nvd": 412
  }
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `feed_id` | string | Identificador do feed. |
| `total_items` | inteiro | Itens totais na janela rolante. |
| `items_today` | inteiro | Itens publicados no dia corrente UTC. |
| `items_this_week` | inteiro | Itens publicados nos últimos sete dias. |
| `last_updated` | string ou nulo | Data/hora ISO 8601 UTC da última indexação. |
| `categories` | objeto | Distribuição por categoria dentro do feed. |
| `sources` | objeto | Distribuição por fonte upstream. |

### Exemplo

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve/stats" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/all/summary

Retorna um resumo consolidado de todos os feeds disponíveis. Cache de 30 segundos no servidor.

Use este endpoint em telas de monitoração e dashboards onde a granularidade ao segundo não importa. Para detecção de novos itens em tempo real, use `GET /api/feeds/{feed_id}/latest`.

### Resposta de sucesso

```json
{
  "feeds": [
    {
      "feed_id": "cve",
      "name": "CVE Monitor",
      "category": "vulnerabilities",
      "item_count": 412,
      "last_updated": "2026-05-13T18:00:00Z",
      "status": "active"
    }
  ],
  "total_feeds": 9,
  "total_items": 2487,
  "timestamp": "2026-05-13T18:42:11Z"
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `feeds[].feed_id` | string | Identificador do feed. |
| `feeds[].name` | string | Nome de exibição. |
| `feeds[].category` | string | Categoria lógica. |
| `feeds[].item_count` | inteiro | Itens disponíveis na janela rolante. |
| `feeds[].last_updated` | string ou nulo | Data/hora ISO 8601 UTC da última indexação. |
| `feeds[].status` | string | `active` quando o feed tem itens. `empty` quando não há nenhum item disponível na janela. |
| `total_feeds` | inteiro | Tamanho da lista `feeds`. |
| `total_items` | inteiro | Soma de `item_count` em todos os feeds. |
| `timestamp` | string | Data/hora ISO 8601 UTC da geração do resumo. |

### Exemplo

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/all/summary" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Erros comuns

`401 Unauthorized`. Token ausente, mal formado ou desconhecido.

`404 Not Found`. `feed_id` desconhecido em endpoints que recebem identificador. O corpo de erro lista os identificadores válidos.

`429 Too Many Requests`. Mais de 120 requisições por minuto a partir do mesmo IP, somando todas as rotas da Sheep API.

Consulte `../errors.md` para detalhes.

## Observações de uso

### Janela rolante

Cada feed mantém aproximadamente os últimos 30 dias de itens. Itens antigos são descartados conforme novos chegam. Para arquivamento de longo prazo, espelhe os itens em armazenamento próprio assim que forem publicados.

### Frequência de polling

`update_interval` indica o intervalo nominal de atualização do feed na fonte. Não é necessário fazer poll com frequência maior que esse intervalo. Polling agressivo desperdiça quota de rate-limit global da API sem entregar dado novo.

### Deduplicação no cliente

A API garante que cada item é único dentro do feed por `id`. Se você consome múltiplos feeds que indexam fontes sobrepostas, faça deduplicação adicional no cliente usando `id + url`.

### Paginação estável

A ordem dos itens em `GET /api/feeds/{feed_id}` é por data decrescente (mais recente primeiro). Para paginação confiável em janelas grandes, combine `since` com `limit`/`offset` em vez de paginar apenas com offset, que pode deslocar conforme novos itens entram.
