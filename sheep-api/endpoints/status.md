# GET /api/ai/status

Retorna o estado operacional do serviço de IA. Endpoint público, projetado para health checks externos e monitoração contínua.

## Endpoint

```
GET https://sheep.byfranke.com/api/ai/status
```

## Headers obrigatórios

Nenhum. Este endpoint não exige autenticação.

## Corpo da requisição

Não aplicável. Este endpoint é GET.

## Resposta de sucesso

`HTTP 200 OK`

```json
{
  "service": "sheep",
  "status": "operational"
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `service` | string | Identificador do serviço. Sempre `sheep`. |
| `status` | string | Estado operacional. Um de `operational` ou `degraded`. |

### Valores de `status`

* `operational`. O serviço está respondendo normalmente. `/ask`, `/analyze` e demais rotas autenticadas devem funcionar sem incidente.
* `degraded`. O serviço está indisponível ou em estado degradado. Requisições a `/ask` e `/analyze` podem falhar com `500` ou `503` até a normalização.

## Erros

Este endpoint não retorna erros típicos. Em incidentes severos, pode retornar `502` ou `503` da camada de borda antes mesmo de chegar ao serviço.

## Exemplos curl

Healthcheck simples.

```bash
curl -X GET "https://sheep.byfranke.com/api/ai/status"
```

Healthcheck com código HTTP em script de monitoração.

```bash
code=$(curl -s -o /dev/null -w "%{http_code}" "https://sheep.byfranke.com/api/ai/status")
if [ "$code" != "200" ]; then
  echo "Sheep API offline (HTTP $code)"
  exit 1
fi
```

Healthcheck com leitura do campo `status`. Requer `jq`.

```bash
status=$(curl -s "https://sheep.byfranke.com/api/ai/status" | jq -r '.status')
if [ "$status" != "operational" ]; then
  echo "Sheep API degradada: $status"
  exit 1
fi
```

Healthcheck condicional antes de despachar lote. Combina com `GET /api/profile` para validar saúde do serviço e quota disponível.

```bash
status=$(curl -s "https://sheep.byfranke.com/api/ai/status" | jq -r '.status')
if [ "$status" = "operational" ]; then
  curl -s -X POST "https://sheep.byfranke.com/api/ai/ask" \
    -H "X-Sheep-Token: shp_API_KEY_AQUI" \
    -H "Content-Type: application/json" \
    -d '{"question": "..."}'
fi
```

## Observações de uso

### Custo

Este endpoint não consome quota de tokens Sheep e não exige autenticação. Pode ser consultado livremente.

### Frequência recomendada

Respeite a etiqueta de uma consulta por minuto por host de monitoração. Bursts contínuos não fornecem informação adicional e desperdiçam infraestrutura compartilhada.

### Diferenciação de falhas

Quando seu cliente receber erros transitórios em `/ask` ou `/analyze`, consultar `GET /api/ai/status` ajuda a distinguir entre falha do seu cliente (rede local, certificado, payload inválido) e degradação do serviço (`degraded`).

Combine essa informação com a estratégia de retentativa descrita em `../errors.md`:

* `operational` + erro 500/503 esporádico no `/ask` → retentativa com backoff curto.
* `degraded` + erro 500/503 no `/ask` → retentativa com backoff longo, ou pausar o pipeline até `operational` voltar.
* `operational` + erro 401/402/403 no `/ask` → problema do cliente. Não retentar antes de corrigir o token ou o pagamento.

### Healthcheck em pipelines de CI

Use este endpoint como pré-condição em pipelines automatizados que dependem da Sheep API. Falhar cedo evita workflows longos que abortariam mais à frente por indisponibilidade do serviço.

### Quando `degraded` aparece

`degraded` significa que TODOS os caminhos internos de servir o modelo estão indisponíveis ao mesmo tempo. Em condições normais, mesmo com falha de um caminho a API continua operacional servindo pelos outros. `degraded` é um sinal forte de incidente operacional.
