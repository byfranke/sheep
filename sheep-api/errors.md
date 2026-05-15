# Contrato de Erros

Todas as respostas de erro da Sheep API seguem o mesmo formato JSON. Esta página descreve o formato e enumera os códigos por classe HTTP.

## Formato da resposta

Erros retornam um objeto com campo `detail`. Quando o detalhe é estruturado, ele traz pelo menos `error` e `message`.

```json
{
  "detail": {
    "error": "quota_exhausted",
    "message": "Monthly token budget exhausted. Renew or upgrade to restore access.",
    "current_period_end": "2026-06-01T00:00:00Z"
  }
}
```

Em alguns erros simples (validação de schema, rate limit), `detail` é uma string humana. Trate ambos os formatos.

O campo `error` é estável. Ramifique comportamento por código, não por texto da mensagem.

## Classes HTTP

A API usa códigos HTTP padrão. Cada classe agrupa um conjunto de códigos de erro lógicos.

### 400 Bad Request

A requisição está malformada ou viola validação de schema.

Causas típicas:

* `question` vazia, com menos de 3 caracteres ou acima de 2500.
* `target` (em `/analyze`) vazio ou acima de 500 caracteres.
* `model` fora do conjunto aceito.
* `type` (em `/analyze`) fora do conjunto aceito.
* Cabeçalho `Content-Type` ausente ou diferente de `application/json` quando o corpo é obrigatório.

Ação. Corrija o cliente antes de retentar. Retentar sem corrigir retorna o mesmo erro.

### 401 Unauthorized

Autenticação falhou. Os códigos comuns são:

* `invalid_token_format`. O valor do header `X-Sheep-Token` não bate com o formato esperado.
* `token_not_found`. O token está bem formado mas não corresponde a uma conta.
* `missing_token`. O header `X-Sheep-Token` não foi enviado.

Ação. Revise o header. Confira se o token vigente é o que está sendo enviado. Se houver suspeita de vazamento, rotacione imediatamente pelo caminho usado na emissão (link no e-mail vigente para Pro, Pro Max e Enterprise; `/token` no Discord para Black Sheep).

### 402 Payment Required

A autenticação passou mas a assinatura impede a chamada. Os códigos comuns são:

* `subscription_period_expired`. O período da assinatura terminou. Renove ou ative um novo código para restaurar o acesso.
* `subscription_not_active`. Pagamento falhou, foi cancelado ou está pausado. O campo `subscription_status` traz o estado de billing para correlação com o suporte. Atualize sua forma de pagamento na Sheep Store.
* `quota_exhausted`. O saldo de tokens Sheep no período atual é insuficiente. Aguarde a virada do período ou contrate um add-on. Em assinaturas em avaliação (`subscription.status` = `trialing`), o teto considerado é o teto reduzido de avaliação do plano, descrito em `plans-and-quota.md`.

Ação. Verifique seu plano em `GET /api/profile`. Renove, ative novo gift card ou contrate add-on conforme o caso.

### 403 Forbidden

A autenticação passou e a assinatura está ativa, mas a operação solicitada não é permitida para o plano.

* `model_not_allowed`. O plano vigente não inclui o modelo informado em `model`. Por exemplo, Pro pedindo `sage`.

Ação. Use um modelo dentro da lista de `plan.allowed_models` em `GET /api/profile`, ou faça upgrade do plano.

### 429 Too Many Requests

O cliente excedeu o limite de taxa do endpoint. Há um único código lógico associado.

* `rate_limit_exceeded`. O número de chamadas por minuto ultrapassou o teto descrito em `rate-limits.md`.

A resposta sempre inclui o cabeçalho `Retry-After` com o tempo em segundos.

Ação. Respeite o `Retry-After`. Implemente backpressure no cliente. Tentar antes do prazo retorna outro 429 e aumenta o risco de bloqueio temporário.

### 404 Not Found

Aplica-se apenas a endpoints com identificador na URL.

* Em `GET /api/feeds/{feed_id}`, um `feed_id` desconhecido retorna 404 com a lista dos identificadores válidos.

Ação. Corrija o identificador. Use `GET /api/feeds` para listar feeds disponíveis.

### 500 Internal Server Error

Erro inesperado no servidor.

Ação. Retentativa com backoff razoável. Se o erro persistir, abra um chamado no canal de suporte com o horário aproximado.

### 503 Service Unavailable

Indisponibilidade total da camada de IA.

Ação. Retentativa com backoff exponencial. Sugestão: três tentativas espaçadas em 2, 5 e 15 segundos. Esse cenário é raro.

## Política de retentativa

Aplique retentativa apenas a erros transitórios.

* Retente: 429 (respeitando `Retry-After`), 500 e 503.
* Não retente: 400, 401, 402, 403, 404.

Códigos da família 4xx exigem correção no cliente, na credencial ou na conta antes que a próxima tentativa tenha chance de sucesso.

## Códigos desconhecidos

Trate códigos desconhecidos da família 5xx como transitórios e aplique retentativa cautelosa. Novos códigos podem ser adicionados sem aviso. Remoções e renomeações de códigos passam pelo aviso prévio descrito em `README.md`.
