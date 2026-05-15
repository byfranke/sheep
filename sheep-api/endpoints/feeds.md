# Feeds de Threat Intelligence

A Sheep API expõe um conjunto de feeds curados de Threat Intelligence. Cada feed reúne itens publicados por fontes selecionadas e expõe uma janela rolante de aproximadamente 30 dias. Use os feeds para alimentar SIEMs, dashboards internos e workflows de automação.

Há cinco operações disponíveis sobre os feeds.

* `GET /api/feeds/` lista todos os feeds disponíveis.
* `GET /api/feeds/categories` lista as categorias e os feeds em cada uma.
* `GET /api/feeds/{feed_id}` retorna itens de um feed específico com filtros e paginação.
* `GET /api/feeds/{feed_id}/latest` retorna os itens mais recentes de um feed.
* `GET /api/feeds/{feed_id}/stats` retorna estatísticas agregadas do feed.
* `GET /api/feeds/all/summary` retorna um resumo consolidado de todos os feeds.

Os feeds não consomem tokens Sheep. As rotas de feeds não têm rate-limit dedicado e respeitam apenas o limite global de 120 requisições por minuto por IP aplicado a toda a Sheep API.

## Headers obrigatórios

Todas as operações de feeds exigem o header de autenticação.

```
X-Sheep-Token: shp_API_KEY_AQUI
```

## Feeds disponíveis

Cada feed tem um identificador estável usado em `{feed_id}`.

* `cve`. Vulnerabilidades críticas recém-publicadas.
* `ransomware`. Vítimas e atividade de operações de ransomware reportadas em sites públicos.
* `threat_intel`. Relatórios e atualizações de threat intelligence.
* `apt_infrastructure`. Indicadores de infraestrutura associada a operações APT.
* `data_leak`. Eventos de vazamento de dados corporativos.
* `ics_scada`. Vulnerabilidades e alertas em sistemas de controle industrial.
* `kaspersky`. Pesquisa e alertas publicados pela Kaspersky.
* `ioc_stream`. Stream em tempo quase real de IPs, URLs e hashes maliciosos.
* `rss_news`. Notícias agregadas de cibersegurança.

Para descobrir a lista oficial em runtime, use `GET /api/feeds/`.

## GET /api/feeds/

Lista todos os feeds disponíveis com metadados básicos.

Resposta de sucesso:

```json
{
  "feeds": [
    {
      "id": "cve",
      "name": "CVE Monitor",
      "description": "Critical vulnerabilities from public advisories",
      "category": "vulnerabilities",
      "update_interval": 60,
      "last_updated": "2026-05-13T18:00:00Z",
      "item_count": 412
    }
  ],
  "total": 9
}
```

| Campo | Descrição |
|---|---|
| `feeds[].id` | Identificador do feed para uso em outras chamadas. |
| `feeds[].name` | Nome de exibição. |
| `feeds[].description` | Resumo de uma linha do que o feed agrega. |
| `feeds[].category` | Categoria lógica (vulnerabilities, ransomware, threat_intelligence, infrastructure, data_breach, ics, iocs, news). |
| `feeds[].update_interval` | Intervalo nominal de atualização do feed em segundos. |
| `feeds[].last_updated` | Data/hora ISO 8601 UTC da última indexação. |
| `feeds[].item_count` | Número de itens disponíveis na janela atual. |
| `total` | Tamanho da lista. |

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/categories

Lista as categorias e os feeds em cada categoria.

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
    "iocs": ["ioc_stream"],
    "news": ["rss_news"]
  },
  "total": 8
}
```

## GET /api/feeds/{feed_id}

Retorna itens de um feed específico, com filtros opcionais e paginação.

Parâmetros de query string:

| Parâmetro | Tipo | Descrição |
|---|---|---|
| `limit` | inteiro | Máximo de itens a retornar. Faixa 1 a 500. Padrão 50. |
| `offset` | inteiro | Deslocamento para paginação. Padrão 0. |
| `since` | string ISO 8601 | Filtra para itens publicados após a data informada. |
| `severity` | string | Filtra por severidade. Aceita `high`, `medium`, `low`. |
| `category` | string | Filtra pelo campo `category` do item. |

Resposta de sucesso:

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

Os campos dentro de `items` variam por feed. Os campos `id`, `title`, `url`, `published_at`, `severity` e `tags` aparecem na maior parte dos feeds. Campos adicionais específicos da fonte podem aparecer (CVSS para CVEs, ator para ransomware, etc.).

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/cve?limit=10&severity=high" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

`feed_id` desconhecido retorna `404 Not Found` com a lista de identificadores válidos.

## GET /api/feeds/{feed_id}/latest

Retorna os itens mais recentes de um feed. Atalho útil para o caso de uso mais comum.

Parâmetros de query string:

| Parâmetro | Tipo | Descrição |
|---|---|---|
| `count` | inteiro | Número de itens. Faixa 1 a 100. Padrão 10. |

Resposta de sucesso:

```json
{
  "feed_id": "cve",
  "items": [],
  "count": 10,
  "last_updated": "2026-05-13T18:00:00Z"
}
```

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/ransomware/latest?count=20" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## GET /api/feeds/{feed_id}/stats

Retorna estatísticas agregadas do feed.

Resposta de sucesso:

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
    "advisory-feed": 412
  }
}
```

| Campo | Descrição |
|---|---|
| `total_items` | Itens totais na janela rolante do feed. |
| `items_today` | Itens cuja publicação caiu no dia corrente UTC. |
| `items_this_week` | Itens publicados nos últimos sete dias. |
| `categories` | Distribuição por categoria dentro do feed. |
| `sources` | Distribuição por fonte upstream. |

## GET /api/feeds/all/summary

Retorna um resumo consolidado de todos os feeds disponíveis. Útil para dashboards e telas de monitoração.

Resposta de sucesso:

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

| Campo | Descrição |
|---|---|
| `feeds[].feed_id` | Identificador do feed. |
| `feeds[].name` | Nome de exibição. |
| `feeds[].category` | Categoria lógica. |
| `feeds[].item_count` | Itens disponíveis na janela rolante. |
| `feeds[].last_updated` | Data/hora ISO 8601 UTC da última indexação. |
| `feeds[].status` | `active` quando o feed tem itens. `empty` quando não há nenhum item disponível. |
| `total_feeds` | Tamanho da lista `feeds`. |
| `total_items` | Soma de `item_count` em todos os feeds. |
| `timestamp` | Data/hora ISO 8601 UTC da geração do resumo. |

A resposta é cacheada por curtos períodos. Não use este endpoint para detectar novos itens em tempo real — para esse caso, use `GET /api/feeds/{feed_id}/latest`.

Exemplo:

```bash
curl -X GET "https://sheep.byfranke.com/api/feeds/all/summary" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Erros comuns

`401 Unauthorized`. Token ausente ou inválido.

`404 Not Found`. `feed_id` desconhecido em endpoints que recebem identificador.

`429 Too Many Requests`. Mais de 120 requisições por minuto a partir do mesmo IP, somando todas as rotas da Sheep API.

Consulte `../errors.md` para detalhes.
