# GET /api/profile

Retorna o perfil da conta autenticada: plano vigente, modelos liberados, contadores de uso do período corrente e add-ons ativos.

Use este endpoint para implementar dashboards de consumo, alertas internos e validação pré-flight antes de despachar lotes grandes.

## Endpoint

```
GET https://sheep.byfranke.com/api/profile
```

## Headers obrigatórios

```
X-Sheep-Token: shp_API_KEY_AQUI
```

## Corpo da requisição

Não aplicável. Este endpoint é GET.

## Resposta de sucesso

`HTTP 200 OK`

```json
{
  "kind": "subscriber",
  "plan": {
    "id": "pro",
    "name": "Sheep Pro",
    "monthly_token_budget": 300000,
    "allowed_models": ["auto", "scout", "hunter"]
  },
  "addons": [],
  "subscription": {
    "status": "active",
    "current_period_end": "2026-06-01T00:00:00Z",
    "cancel_at_period_end": false,
    "trial_end": null,
    "billing_cycle_months": 1
  },
  "usage": {
    "current_period_tokens": 142387,
    "current_period_budget": 300000,
    "monthly_token_budget": 300000,
    "base_token_budget": 300000,
    "addon_token_budget": 0,
    "tokens_remaining": 157613,
    "last_call_at": "2026-05-13T18:30:42Z"
  }
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `kind` | string | Sempre `subscriber` para chamadas autenticadas com `X-Sheep-Token`. |
| `plan.id` | string | Identificador interno do plano. Um de `pro`, `pro_max`, `enterprise`, `black_sheep`, `black_sheep_trial`. |
| `plan.name` | string | Nome de exibição do plano. |
| `plan.monthly_token_budget` | inteiro | Quota base mensal do plano em tokens Sheep, sem considerar add-ons. |
| `plan.allowed_models` | array de strings | Identificadores de modelo permitidos pelo plano. |
| `addons` | array de objetos | Lista de add-ons recorrentes ativos. Vazio quando não há add-ons. |
| `subscription.status` | string | Estado da assinatura. `active` é o estado normal. Outros valores indicam pendência de pagamento ou cancelamento. |
| `subscription.current_period_end` | string | Data/hora ISO 8601 UTC do fim do período corrente. |
| `subscription.cancel_at_period_end` | booleano | `true` quando o cliente solicitou cancelamento mas o período corrente ainda vale. |
| `subscription.trial_end` | string ou nulo | Data/hora ISO 8601 UTC do fim de período de avaliação, quando aplicável. |
| `subscription.billing_cycle_months` | inteiro | Duração do período corrente em meses. Vale 1 para mensal, 12 para anual, e o número de meses do gift card para Black Sheep. |
| `usage.current_period_tokens` | inteiro | Tokens Sheep consumidos no período corrente. |
| `usage.current_period_budget` | inteiro | Teto efetivo do período corrente. Quando `subscription.status` é `active`: igual a `base_token_budget` mais `addon_token_budget`. Quando `subscription.status` é `trialing`: igual ao teto de avaliação do plano (ver `plans-and-quota.md` para os valores), sem add-ons. |
| `usage.monthly_token_budget` | inteiro | Quota mensal do plano somada à quota mensal dos add-ons. |
| `usage.base_token_budget` | inteiro | Quota base do plano para o período inteiro. |
| `usage.addon_token_budget` | inteiro | Soma da quota de add-ons para o período inteiro. |
| `usage.tokens_remaining` | inteiro | Diferença entre `current_period_budget` e `current_period_tokens`. Mínimo zero. |
| `usage.last_call_at` | string ou nulo | Data/hora ISO 8601 UTC da última chamada da conta. `null` quando não houve chamada no período corrente. |

### Estrutura de cada item em `addons`

```json
{
  "id": "tokens_2m",
  "name": "Sheep +2M Tokens",
  "extra_tokens_monthly": 2000000,
  "extra_tokens_period": 2000000,
  "status": "active",
  "current_period_end": "2026-06-01T00:00:00Z",
  "cancel_at_period_end": false
}
```

`extra_tokens_period` já vem escalonado pelo número de meses do período. Para um cliente anual, o valor é a quota mensal multiplicada por 12.

## Erros comuns

`401 Unauthorized`. Token ausente ou inválido.

`429 Too Many Requests`. Mais de 30 requisições por minuto neste endpoint.

## Exemplo curl

```bash
curl -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

## Observações de uso

Este endpoint não consome quota de tokens Sheep. Pode ser consultado livremente, respeitando o limite de 30 requisições por minuto.

Use os campos do bloco `usage` para construir alertas internos. Exemplos práticos:

* Alertar quando `tokens_remaining` cai abaixo de 10% de `current_period_budget`.
* Pausar pipelines automáticos quando `subscription.status` deixa de ser `active`.
* Recusar usuário no painel quando o modelo desejado não está em `plan.allowed_models`.
