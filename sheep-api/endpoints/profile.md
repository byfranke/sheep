# GET /api/profile

Retorna o perfil da conta autenticada: plano vigente, modelos liberados, contadores de uso do período corrente, add-ons ativos e outros tokens associados ao mesmo e-mail.

Use este endpoint para implementar dashboards de consumo, alertas internos, validação pré-flight antes de despachar lotes grandes e troca de token em cliente multi-plano.

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
    "name": "Sheep Plus",
    "monthly_token_budget": 300000,
    "allowed_models": ["auto", "scout", "hunter"]
  },
  "addons": [],
  "active_token_hint": "a3b1f0",
  "other_tokens": [],
  "subscription": {
    "status": "active",
    "current_period_end": "2026-06-01T00:00:00Z",
    "cancel_at_period_end": false,
    "cancel_at": null,
    "canceled_at": null,
    "access_revoked": false,
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
| `plan.id` | string | Identificador do plano. Um de `pro`, `pro_max`, `enterprise`, `black_sheep`, `black_sheep_trial`. |
| `plan.name` | string | Nome de exibição do plano. |
| `plan.monthly_token_budget` | inteiro | Quota base mensal do plano em tokens Sheep, sem considerar add-ons. |
| `plan.allowed_models` | array de strings | Identificadores de modelo permitidos pelo plano. Usar para gatear o seletor de modelo no cliente. |
| `addons` | array de objetos | Lista de add-ons recorrentes ativos. Vazio quando não há add-ons. Detalhe na seção abaixo. |
| `active_token_hint` | string | Sufixo (últimos 6 caracteres) do token enviado nesta requisição. Identificação visual, NÃO autenticação. |
| `other_tokens` | array de objetos | Outros tokens ativos vinculados ao mesmo e-mail. Vazio na maioria dos casos. Detalhe na seção abaixo. |
| `subscription.status` | string | Estado da assinatura. `active`, `trialing`, `past_due`, `canceled`, `unpaid`, `incomplete`, ou rótulo equivalente. |
| `subscription.current_period_end` | string | Data/hora ISO 8601 UTC do fim do período corrente. |
| `subscription.cancel_at_period_end` | booleano | `true` quando o cliente solicitou cancelamento mas o período corrente ainda vale. |
| `subscription.cancel_at` | string ou nulo | Quando o cancelamento foi agendado para uma data específica. ISO 8601 UTC. |
| `subscription.canceled_at` | string ou nulo | Quando o cancelamento efetivamente ocorreu. ISO 8601 UTC. |
| `subscription.access_revoked` | booleano | `true` quando o acesso está revogado AGORA. Combinação derivada de `cancel_at_period_end`, `cancel_at` ou `canceled_at`. Use este campo para decidir se o cliente pode chamar `/ask` e `/analyze` neste momento. |
| `subscription.trial_end` | string ou nulo | Data/hora ISO 8601 UTC do fim do período de avaliação, quando aplicável. |
| `subscription.billing_cycle_months` | inteiro | Duração do período corrente em meses. `1` para mensal, `12` para anual, `3`/`6`/`12` para Black Sheep gift cards. |
| `usage.current_period_tokens` | inteiro | Tokens Sheep consumidos no período corrente. |
| `usage.current_period_budget` | inteiro | Teto efetivo do período corrente. Em `active`: `base_token_budget + addon_token_budget`. Em `trialing`: teto reduzido de avaliação do plano (sem add-ons). |
| `usage.monthly_token_budget` | inteiro | Quota mensal do plano somada à quota mensal dos add-ons. |
| `usage.base_token_budget` | inteiro | Quota base do plano escalonada para o período inteiro. |
| `usage.addon_token_budget` | inteiro | Soma da quota de add-ons escalonada para o período inteiro. `0` durante `trialing`. |
| `usage.tokens_remaining` | inteiro | `current_period_budget - current_period_tokens`. Mínimo zero. |
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

### Estrutura de cada item em `other_tokens`

Aparece quando o mesmo e-mail tem mais de uma assinatura ativa, por exemplo Sheep Pro em paralelo com um gift card Black Sheep. Cada item descreve um token DIFERENTE do que está sendo usado nesta requisição.

```json
{
  "token_hint": "c8e2a4",
  "plan_id": "black_sheep",
  "plan_name": "Black Sheep",
  "status": "active",
  "access_revoked": false,
  "cancel_at": null,
  "canceled_at": null,
  "current_period_end": "2027-05-13T00:00:00Z",
  "trial_end": null,
  "tokens_consumed": 12450,
  "tokens_budget": 2000000,
  "tokens_remaining": 1987550
}
```

| Campo | Descrição |
|---|---|
| `token_hint` | Últimos 6 caracteres do outro token. Identificação visual para o usuário escolher qual token usar. |
| `plan_id` / `plan_name` | Plano associado ao outro token. |
| `status` | Status da assinatura associada. |
| `access_revoked` | `true` quando o outro token está cancelado. |
| `cancel_at` / `canceled_at` | Datas de cancelamento, se houver. |
| `current_period_end` | Fim do período corrente do outro token. |
| `trial_end` | Fim do período de avaliação, quando aplicável. |
| `tokens_consumed` / `tokens_budget` / `tokens_remaining` | Contadores de uso do período corrente do outro token. |

Quotas NÃO são somadas entre tokens. Cada token tem seu próprio orçamento independente. O cliente escolhe qual token enviar em `X-Sheep-Token` em cada chamada.

## Erros comuns

`401 Unauthorized`. Token ausente ou inválido.

`429 Too Many Requests`. Mais de 30 requisições por minuto neste endpoint.

## Exemplos curl

Consulta básica.

```bash
curl -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

Pré-flight antes de despachar lote grande. Usar `usage.tokens_remaining` para decidir se cabe ou se precisa esperar próximo ciclo.

```bash
curl -s -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  | jq '.usage.tokens_remaining'
```

Validação de acesso. Recusar comando no painel quando `access_revoked` é `true`.

```bash
curl -s -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  | jq '.subscription.access_revoked'
```

Validação de modelo. Antes de oferecer Sage no seletor, conferir se o plano cobre.

```bash
curl -s -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  | jq '.plan.allowed_models | contains(["sage"])'
```

## Observações de uso

### Custo

Este endpoint não consome quota de tokens Sheep. Pode ser consultado livremente dentro do limite de 30 requisições por minuto.

### Pré-flight de batch

Sempre que um pipeline está prestes a despachar uma rajada de chamadas para `/ask` ou `/analyze`, valide `tokens_remaining` antes. Recusar localmente o batch é melhor do que receber `quota_exceeded` no meio do processamento e ter que desfazer estado.

### Trial e budget reduzido

Quando `subscription.status` é `trialing`, `current_period_budget` reflete o teto reduzido de avaliação do plano (consulte `../plans-and-quota.md`). Add-ons não contam durante o trial. Ao transicionar para `active`, o budget volta a incluir add-ons automaticamente.

### Multi-token

Um cliente pode ter mais de um token simultâneo, por exemplo Pro Max para uso diário e um gift card Black Sheep como backup. O array `other_tokens` é o canal de descoberta. Use `token_hint` (últimos 6 caracteres) para identificar visualmente o token sem nunca pedir o valor completo de volta ao usuário.

### Cache do cliente

A resposta deste endpoint é volátil: tokens consumidos mudam a cada chamada de `/ask` ou `/analyze`. Cacheie por períodos curtos (segundos) ou consulte sempre que precisar de leitura precisa.

### Alertas internos sugeridos

* Alertar quando `usage.tokens_remaining` cai abaixo de 10% de `usage.current_period_budget`.
* Pausar pipelines automáticos quando `subscription.status` deixa de ser `active`.
* Notificar admin quando `subscription.access_revoked` vira `true` para evitar fila de chamadas que vão receber 402.
* Avisar usuário no painel quando o modelo desejado não está em `plan.allowed_models`.
