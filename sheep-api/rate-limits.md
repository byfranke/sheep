# Limites de Taxa

A Sheep API aplica dois mecanismos independentes de controle de uso:

* Quota mensal de tokens Sheep, descrita em `plans-and-quota.md`.
* Taxa máxima de requisições por minuto, descrita aqui.

## Limites por endpoint

Os limites de taxa aplicam-se por token de API, em janela deslizante de 60 segundos.

* `POST /api/ai/ask`. Até 100 requisições por minuto.
* `POST /api/ai/analyze`. Até 100 requisições por minuto.
* `GET /api/profile`. Até 30 requisições por minuto.
* `GET /api/feeds/*`. Até 30 requisições por minuto.
* `GET /api/ai/status`. Não exige autenticação e não tem limite explícito por token. Respeite o uso razoável de uma consulta por minuto.

Os limites de `/ask` e `/analyze` são independentes. Esgotar o limite de um endpoint não bloqueia o outro.

## Headers de controle

Toda resposta de endpoint com limite explícito inclui os seguintes cabeçalhos.

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1715620920
```

* `X-RateLimit-Limit`. Teto da janela.
* `X-RateLimit-Remaining`. Requisições restantes antes da próxima rejeição.
* `X-RateLimit-Reset`. Timestamp Unix do momento em que a janela atual será considerada expirada para a contagem.

Use esses valores para implementar fila e backpressure no cliente.

## Comportamento ao exceder

Quando o limite é excedido, o servidor responde com `429 Too Many Requests`.

A resposta inclui o cabeçalho `Retry-After` em segundos. Esse valor indica o tempo mínimo até a próxima requisição elegível.

Exemplo:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 12
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1715620920
Content-Type: application/json

{
  "detail": "Rate limit exceeded: max 100 /ask requests per minute."
}
```

Respeite o `Retry-After`. Retentativas antes do prazo retornam outro 429 e aumentam o risco de bloqueio temporário por abuso.

## Limites e planos

Os limites de taxa são fixos por endpoint. Eles não escalonam com o plano. O desenho assume que mesmo cargas intensas de SIEM ou SOAR cabem dentro de 100 chamadas por minuto.

Se o seu caso de uso exige taxa sustentada acima dos limites publicados, entre em contato pelo canal comercial em `https://byfranke.com/#Contact`.

## Padrão recomendado para volume

Para processar grandes lotes de IOCs ou perguntas, evite loops apertados. Use uma fila com paralelismo controlado, por exemplo dez chamadas simultâneas com fila atrás.

Antes de despachar um lote grande, consulte `GET /api/profile` para confirmar que há saldo de tokens Sheep suficiente. Quota e limite de taxa são gates independentes; passar no rate limit não garante passar na quota.
