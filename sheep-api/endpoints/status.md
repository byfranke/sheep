# GET /api/ai/status

Retorna o estado operacional do serviço de IA. Endpoint público, projetado para health checks externos e monitoração.

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

* `operational`. O serviço está respondendo normalmente.
* `degraded`. O serviço está indisponível ou em estado degradado. Requisições a `/ask` e `/analyze` podem falhar até a normalização.

## Erros

Este endpoint não retorna erros típicos. Em incidentes severos, pode retornar `502` ou `503`.

## Exemplo curl

```bash
curl -X GET "https://sheep.byfranke.com/api/ai/status"
```

## Observações de uso

Este endpoint não consome quota e não exige autenticação. Pode ser consultado livremente.

Para monitoração automática, respeite a etiqueta de uma consulta por minuto. Bursts contínuos não fornecem informação adicional e desperdiçam infraestrutura.

Quando seu sistema receber erros transitórios em outros endpoints, consultar `GET /api/ai/status` ajuda a distinguir entre falha do seu cliente e degradação do serviço. Combine essa informação com a estratégia de retentativa descrita em `../errors.md`.
