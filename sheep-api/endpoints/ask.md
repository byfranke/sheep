# POST /api/ai/ask

Recebe uma pergunta em linguagem natural sobre cibersegurança, threat intelligence ou análise de incidentes. Retorna uma resposta gerada pelo modelo de IA selecionado.

Este é o endpoint mais usado da API. Use-o para conversação livre, definições, perfil de grupos APT, explicação de técnicas, narrativa sobre logs colados na pergunta e qualquer pergunta de CTI que não exija um IOC estruturado como argumento.

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
| `model` | string | não | Identificador do modelo. Valores aceitos: `auto`, `scout`, `hunter`, `sage`. Padrão: `auto`. Consulte `../models.md`. |
| `max_tokens` | inteiro | não | Limite manual de tokens na resposta. Faixa: 100 a 2000. Quando omitido ou nulo, a API escolhe automaticamente com base na complexidade da pergunta. |

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
| `served_by` | string | Tier que atendeu de fato. Um de `scout`, `hunter`, `sage`. |
| `requested_model` | string ou nulo | Reservado para sinalizar rebaixamento operacional do modelo solicitado. Atualmente sempre `null` em produção. Quando começar a ser preenchido, virá com o identificador do modelo originalmente pedido para que o cliente possa avisar o usuário. |
| `tokens_used` | inteiro | Tokens Sheep cobrados da sua quota, já com o multiplicador do modelo aplicado. |
| `usage.prompt_tokens` | inteiro | Tokens reais consumidos pelo prompt enviado ao modelo. |
| `usage.completion_tokens` | inteiro | Tokens reais consumidos pela resposta gerada. |
| `usage.total_tokens` | inteiro | Soma de `prompt_tokens` e `completion_tokens` em tokens reais, antes do multiplicador. |
| `usage.estimated` | booleano | `true` quando a contagem foi estimada pelo comprimento do texto em vez de reportada pelo engine. |
| `timestamp` | string | Data/hora UTC da geração da resposta no formato ISO 8601. |
| `error` | string ou nulo | `null` em sucesso. |

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

* `model_not_allowed`. O plano vigente não inclui o modelo solicitado.

`429 Too Many Requests`

* `rate_limit_exceeded`. Mais de 100 requisições por minuto neste endpoint. O header `Retry-After` indica o tempo de espera.

`500 Internal Server Error` ou `503 Service Unavailable`

* Falha transitória. Aplique retentativa com backoff exponencial.

Consulte `../errors.md` para a lista completa.

## Exemplo curl

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Explique o Diamond Model aplicado a um incidente de ransomware.",
    "model": "hunter"
  }'
```

## Observações de uso

Perguntas curtas ou de natureza casual (saudações, perguntas sobre o próprio serviço, pedidos de ajuda genéricos) são respondidas em modo enxuto com baixo consumo de tokens. A API não recusa interações leves.

A pergunta pode chegar em qualquer idioma. A resposta é gerada no idioma da pergunta. Para forçar idioma específico, deixe explícito dentro do texto da pergunta, por exemplo: "Responda em português."

Quando a pergunta contém IOCs detectáveis (IP, domínio, hash, URL, CVE), a API enriquece automaticamente o prompt com contexto de reputação antes de chamar o modelo. Esse comportamento é interno e adiciona tokens ao prompt, refletido em `usage.prompt_tokens`. Para análise de um IOC isolado com formato de resposta estruturado, prefira `POST /api/ai/analyze`.
