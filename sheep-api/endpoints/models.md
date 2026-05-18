# GET /api/ai/models

Retorna a lista oficial de modelos disponíveis na Sheep API. Endpoint público, projetado para que clientes (CLIs, dashboards, frontends) renderizem um seletor de modelo sem precisar autenticar primeiro.

## Endpoint

```
GET https://sheep.byfranke.com/api/ai/models
```

## Headers obrigatórios

Nenhum. Este endpoint não exige autenticação.

## Corpo da requisição

Não aplicável. Este endpoint é GET.

## Resposta de sucesso

`HTTP 200 OK`

```json
{
  "models": [
    {
      "id": "auto",
      "display_name": "AUTO",
      "is_default": true,
      "description": {
        "en": "Default. Routes each question to the right tier based on complexity.",
        "pt": "Padrão. Roteia cada pergunta para o tier certo conforme a complexidade."
      }
    },
    {
      "id": "scout",
      "display_name": "Sheep Scout",
      "is_default": false,
      "description": {
        "en": "Fast and light. Use for definitions, quick IOC checks, and short factual questions.",
        "pt": "Rápido e leve. Use para definições, checagens rápidas de IOC e perguntas factuais curtas."
      }
    },
    {
      "id": "hunter",
      "display_name": "Sheep Hunter",
      "is_default": false,
      "description": {
        "en": "Analytical default. Use for APT profiling, framework explanations, multi-source CTI breakdowns.",
        "pt": "Default analítico. Use para perfil de APT, explicação de frameworks, análise CTI multi-fonte."
      }
    },
    {
      "id": "sage",
      "display_name": "Sheep Sage",
      "is_default": false,
      "description": {
        "en": "Deep analysis. Use for complex attribution, correlation across multiple incidents, executive-grade reports.",
        "pt": "Análise profunda. Use para atribuição complexa, correlação entre múltiplos incidentes, relatórios executivos."
      }
    }
  ],
  "default": "auto",
  "legacy_aliases_accepted_until": "2026-07-04"
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `models` | array de objetos | Lista de modelos suportados pela API. |
| `models[].id` | string | Identificador a ser enviado em `model` nas requisições. |
| `models[].display_name` | string | Nome para exibição em interfaces. |
| `models[].is_default` | booleano | `true` para o modelo que a API assume quando o cliente omite o parâmetro. |
| `models[].description.en` | string | Descrição curta em inglês. |
| `models[].description.pt` | string | Descrição curta em português. |
| `default` | string | Identificador do modelo padrão. |
| `legacy_aliases_accepted_until` | string | Data ISO 8601 (YYYY-MM-DD) até a qual a API ainda aceita aliases antigos no campo `model` das requisições. Após essa data, apenas os identificadores listados em `models[].id` são aceitos. |

## Erros

Este endpoint não retorna erros típicos de cliente.

## Exemplos curl

Lista completa.

```bash
curl -X GET "https://sheep.byfranke.com/api/ai/models"
```

Apenas os IDs, para popular um seletor.

```bash
curl -s "https://sheep.byfranke.com/api/ai/models" | jq -r '.models[].id'
```

Validação cruzada com o plano do cliente. Mostra apenas os modelos que ESTA conta pode usar.

```bash
global=$(curl -s "https://sheep.byfranke.com/api/ai/models" | jq -r '.models[].id')
allowed=$(curl -s "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" | jq -r '.plan.allowed_models[]')
comm -12 <(echo "$global" | sort) <(echo "$allowed" | sort)
```

## Quando usar cada modelo

| Tarefa | Modelo recomendado |
|---|---|
| Pergunta conceitual curta ("o que é kerberoasting?") | `scout` |
| Validação rápida de termo ("CVE-2024-3094 é crítico?") | `scout` ou `auto` |
| Perfil de grupo APT, técnicas MITRE associadas | `hunter` |
| Análise de log colado na pergunta | `hunter` |
| Comparação entre famílias de malware | `hunter` |
| Briefing executivo (5 bullets para diretoria) | `sage` |
| Atribuição formal de campanha multi-fonte | `sage` |
| Correlação entre três ou mais incidentes | `sage` |
| Não sei qual escolher | `auto` |

`auto` é o padrão e cobre a maioria dos casos. Use `scout`, `hunter` ou `sage` explicitamente quando você sabe que sua pergunta cai claramente em um dos perfis e quer previsibilidade de latência e custo. Sage é o que mais consome quota e o mais lento; reserve para perguntas onde a profundidade compensa o custo.

## Observações de uso

A lista é a fonte oficial para popular seletores de modelo em interfaces gráficas e CLIs. Novos modelos podem ser adicionados ao longo do tempo. Identificadores existentes não são removidos sem aviso prévio.

Para descobrir quais desses modelos a sua conta tem permissão de usar, consulte `GET /api/profile` e leia `plan.allowed_models`. A interseção entre esta lista global e os modelos do seu plano é o conjunto que deve aparecer no seletor do seu cliente.

Para o significado funcional de cada modelo e quando usar, consulte `../models.md` na raiz da Sheep API.
