# POST /api/ai/ask

Recebe uma pergunta em linguagem natural sobre cibersegurança, threat intelligence ou análise de incidentes. Retorna uma resposta gerada pelo modelo de IA selecionado.

Este é o endpoint mais usado da API. Use-o para conversação livre, definições, perfil de grupos APT, explicação de técnicas, narrativa sobre logs colados na pergunta e qualquer pergunta de CTI que não exija um IOC estruturado como argumento.

Para análise de IOC isolado com saída estruturada (JSON, STIX), use `POST /api/ai/analyze`.

## Endpoint

```
POST https://sheep.byfranke.com/api/ai/ask
```

## Headers obrigatórios

```
X-Sheep-Token: shp_API_KEY_AQUI
Content-Type: application/json
```

## Corpo da requisição

```json
{
  "question": "Quem é o APT29 e quais técnicas MITRE são associadas a ele?",
  "model": "auto",
  "max_tokens": null
}
```

| Campo | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `question` | string | sim | Pergunta em texto livre. De 3 a 2500 caracteres. |
| `model` | string | não | Identificador do modelo. Valores aceitos: `auto`, `scout`, `hunter`, `sage`. Padrão: `auto`. Consulte `models.md`. |
| `max_tokens` | inteiro | não | Limite manual de tokens na resposta. Faixa: 100 a 2000. Quando omitido ou nulo, a API escolhe automaticamente com base na complexidade da pergunta. |

### Escolha do modelo

| Valor | Quando usar | Plano necessário |
|---|---|---|
| `auto` (padrão) | Caso geral. A API roteia entre Scout e Hunter conforme a complexidade da pergunta. Sage nunca é escolhido automaticamente. | Todos os planos pagos. |
| `scout` | Definições curtas, perguntas conceituais, conversação leve, validação rápida de termos. Resposta mais rápida e econômica. | Todos os planos pagos. |
| `hunter` | Perfil de APT, mapeamento MITRE ATT&CK, análise de logs colados na pergunta, comparação entre famílias de malware, triagem de vulnerabilidade. | Todos os planos pagos. |
| `sage` | Briefings executivos, atribuição formal de campanha, correlação multi-incidente, relatório CTI extenso. Resposta mais profunda e mais lenta. | Sheep Pro Max e Sheep Enterprise. |

Para descobrir em runtime quais modelos o plano vigente cobre, consulte `GET /api/profile` (campo `plan.allowed_models`).

## Resposta de sucesso

`HTTP 200 OK`

```json
{
  "success": true,
  "response": "APT29, também conhecido como Cozy Bear, é um grupo de ciberespionagem...",
  "model": "sheep",
  "served_by": "hunter",
  "requested_model": null,
  "tokens_used": 1842,
  "usage": {
    "prompt_tokens": 423,
    "completion_tokens": 498,
    "total_tokens": 921,
    "estimated": false
  },
  "timestamp": "2026-05-13T18:42:11Z",
  "error": null
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `success` | booleano | `true` em respostas bem-sucedidas. |
| `response` | string | Texto gerado pelo modelo. Pode conter Markdown leve. |
| `model` | string | Identificador público do serviço. Sempre `sheep`. |
| `served_by` | string | Tier que efetivamente atendeu a chamada. Um de `scout`, `hunter`, `sage`. Quando `model=auto`, este campo revela qual tier o classificador escolheu. |
| `requested_model` | string ou nulo | Reservado para sinalizar rebaixamento operacional do modelo solicitado. Atualmente sempre `null` em produção. Quando começar a ser preenchido, virá com o identificador do modelo originalmente pedido para que o cliente possa avisar o usuário. |
| `tokens_used` | inteiro | Tokens Sheep cobrados da sua quota nesta chamada. |
| `usage.prompt_tokens` | inteiro | Tokens consumidos pelo prompt enviado ao modelo. |
| `usage.completion_tokens` | inteiro | Tokens consumidos pela resposta gerada. |
| `usage.total_tokens` | inteiro | Soma de `prompt_tokens` e `completion_tokens`. |
| `usage.estimated` | booleano | `true` quando a contagem foi estimada pelo comprimento do texto em vez de reportada pelo engine. |
| `timestamp` | string | Data/hora UTC da geração da resposta no formato ISO 8601. |
| `error` | string ou nulo | `null` em sucesso. |

Para reconciliação de billing, use sempre `tokens_used`. O bloco `usage` é informativo.

## Headers da resposta

Toda resposta inclui headers de rate limit:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 92
X-RateLimit-Reset: 1715620920
```

Consulte `../rate-limits.md` para o significado.

## Erros comuns

`400 Bad Request`

* `question` ausente, vazia, abaixo de 3 caracteres ou acima de 2500 caracteres.
* `model` fora do conjunto aceito.
* `max_tokens` fora da faixa de 100 a 2000.

`401 Unauthorized`

* Header `X-Sheep-Token` ausente, mal formado ou desconhecido.

`402 Payment Required`

* `subscription_period_expired`. Plano vencido.
* `subscription_not_active`. Pagamento não regular.
* `quota_exceeded`. Saldo de tokens Sheep insuficiente para a requisição.

`403 Forbidden`

* `model_not_allowed`. O plano vigente não inclui o modelo solicitado. Caso típico: cliente Sheep Pro requisitando `sage`.

`429 Too Many Requests`

* `rate_limit_exceeded`. Mais de 100 requisições por minuto neste endpoint. O header `Retry-After` indica o tempo de espera.

`500 Internal Server Error` ou `503 Service Unavailable`

* Falha transitória. Aplique retentativa com backoff exponencial.

Consulte `../errors.md` para a lista completa.

## Exemplos curl

Default. Deixe o servidor escolher o tier ideal para sua pergunta.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Quem é o APT29 e quais técnicas MITRE são associadas a ele?"
  }'
```

Modelo Sheep Scout. Definição rápida.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "O que é kerberoasting em uma frase?",
    "model": "scout"
  }'
```

Modelo Sheep Hunter. Análise técnica com saída estruturada por seções.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Explique o Diamond Model aplicado a um incidente de ransomware envolvendo Akira.",
    "model": "hunter"
  }'
```

Modelo Sheep Sage. Briefing executivo, requer Sheep Pro Max ou Enterprise.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Correlacione as últimas três campanhas atribuídas ao Volt Typhoon e proponha o sumário executivo de 5 bullets para diretoria.",
    "model": "sage",
    "max_tokens": 1800
  }'
```

Controle do tamanho da resposta com `max_tokens`. Útil para respostas curtas em automação.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Resuma o impacto do CVE-2024-3094 em duas frases.",
    "max_tokens": 200
  }'
```

## Observações de uso

### Idioma

A pergunta pode chegar em qualquer idioma. A resposta é gerada no idioma da pergunta. Para forçar idioma específico, deixe explícito dentro do texto da pergunta, por exemplo: "Responda em português."

### Perguntas curtas e conversação

Perguntas curtas ou de natureza casual (saudações, perguntas sobre o próprio serviço, pedidos de ajuda genéricos) são respondidas em modo enxuto com baixo consumo de tokens. A API não recusa interações leves.

### Enriquecimento automático de IOCs

Quando a pergunta contém IOCs detectáveis (IP, domínio, hash, URL, CVE), a API enriquece automaticamente o prompt com contexto de reputação antes de chamar o modelo. Esse comportamento é interno e adiciona tokens ao prompt, refletido em `usage.prompt_tokens`. Para análise de um IOC isolado com formato de resposta estruturado para SIEM ou SOAR, prefira `POST /api/ai/analyze`.

### Grounding de notícias recentes

Quando a pergunta menciona um evento corrente (por exemplo "o que aconteceu com a LockBit esta semana"), a API consulta um cache rolante de notícias dos últimos 14 dias e injeta os itens relevantes no prompt como referência. O modelo prioriza essa referência sobre conhecimento de treinamento, reduzindo respostas inventadas sobre eventos recentes. Quando a base não tem nada sobre o evento, o modelo retorna uma negativa honesta ("não tenho itens recentes sobre isso nos últimos 14 dias") em vez de improvisar.

### Cache de respostas

Perguntas idênticas em janela curta podem reusar resultado em cache para reduzir latência. A cobrança em tokens Sheep acompanha o consumo original e é debitada normalmente em cada chamada, mesmo quando o conteúdo vem do cache. Esse comportamento mantém a previsibilidade de billing. Perguntas que contêm IOCs ou referência a eventos correntes nunca são cacheadas.

### Modelo recusa responder

Em casos sensíveis (instruções para atividade ofensiva irrestrita, dados pessoais sensíveis, conteúdo manifestamente ilegal), o modelo pode responder com uma recusa educada. Isso é parte do contrato de segurança e não retorna erro HTTP — `success` continua `true` e a recusa vem em `response`.
