# Compatibilidade com o protocolo Anthropic

A Sheep API expõe um segundo conjunto de endpoints que falam o mesmo formato de wire da Anthropic Messages API. Isso permite que qualquer cliente já escrito para o protocolo Anthropic (SDKs oficiais, agentes de terminal como OpenClaude, plugins de editor que consomem `/v1/messages`) aponte para a Sheep apenas trocando a URL base e o token.

A Sheep não é a Anthropic. Os modelos servidos por estes endpoints são os mesmos modelos Sheep que você já conhece (`scout`, `hunter`, `sage`, `auto`). O protocolo é uma convenção de transporte; a inteligência por trás continua sendo Sheep AI.

## Quando usar este caminho

Use o protocolo Anthropic-compatible quando:

* Você já tem um cliente escrito contra `https://api.anthropic.com/v1/messages` e quer trocar a inteligência sem reescrever a integração.
* Você usa um SDK oficial (`@anthropic-ai/sdk` em Node/TypeScript, `anthropic` em Python) e quer apenas redirecionar a base URL.
* Você usa um agente de terminal como OpenClaude, Cline, Cursor ou Aider que detecta a Anthropic via variáveis de ambiente padrão.
* Você quer function calling (tools) com o mesmo contrato Anthropic.

Use o caminho Sheep-native (`/api/ai/ask`) quando:

* Você está integrando do zero e quer a interface mais simples.
* Você precisa de funcionalidades específicas do Sheep que ainda não foram portadas (enriquecimento explícito de IOC via `/api/ai/analyze`, listagens de feed).
* Você já tem código consumindo o contrato Sheep-native e não quer migrar.

Os dois caminhos convivem em paralelo. Não há plano de remover `/api/ai/ask`. Eles compartilham a mesma identidade, quota e billing — a sua subscription gasta tokens no mesmo bucket independente de qual endpoint você chama.

## Endpoints

```
POST https://sheep.byfranke.com/v1/messages
GET  https://sheep.byfranke.com/v1/models
```

Os dois respondem JSON por padrão. O `/v1/messages` também aceita streaming via Server-Sent Events quando você envia `stream: true` no body.

## Autenticação

O endpoint aceita dois headers, em ordem de precedência. Use apenas um.

```
Authorization: Bearer shp_API_KEY_AQUI
```

ou

```
x-api-key: shp_API_KEY_AQUI
```

Ambos esperam o mesmo formato de token Sheep (`shp_` seguido de 32 caracteres hexadecimais). Não troque o valor por um token de outro provedor.

Headers da Anthropic real que clientes mandam por hábito são aceitos e ignorados em silêncio:

* `anthropic-version: 2023-06-01`
* `anthropic-beta: ...`
* `x-stainless-*`
* `User-Agent: ...` é registrado em audit, mas não influencia a resposta.

A Sheep não exige nenhum desses headers. Não há versionamento por header; quando uma versão nova do contrato vier, ela vivirá em um caminho diferente.

## Modelos disponíveis

O campo `model` na requisição aceita os mesmos nomes que o resto da Sheep API.

| Modelo | Quando usar |
|---|---|
| `scout` | Perguntas rápidas, custo mínimo. |
| `hunter` | Análise técnica de profundidade média. Padrão recomendado para agentes. |
| `sage` | Análise profunda. Disponível apenas em planos Sheep Pro e Sheep Pro Max. |
| `auto` | Roteamento automático entre scout e hunter conforme a complexidade da pergunta. |

O endpoint `GET /v1/models` retorna o subset de modelos liberados para o seu plano. Cliente Sheep Plus recebe `scout`, `hunter` e `auto`; clientes Sheep Pro e Sheep Pro Max recebem os quatro.

Consulte `models.md` para a descrição completa de cada tier.

## Exemplo. Requisição simples

```bash
curl -X POST https://sheep.byfranke.com/v1/messages \
  -H "Authorization: Bearer shp_SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "hunter",
    "max_tokens": 500,
    "messages": [
      {"role": "user", "content": "O que é o APT28?"}
    ]
  }'
```

Resposta (formato Anthropic Message):

```json
{
  "id": "msg_a3f7b2c8d9e0f1a2b3c4d5e6f7a8b9c0",
  "type": "message",
  "role": "assistant",
  "model": "hunter",
  "content": [
    {"type": "text", "text": "APT28, também conhecido como Fancy Bear, é um grupo..."}
  ],
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 12,
    "output_tokens": 184,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0
  }
}
```

## SDK Anthropic oficial

Instale o SDK normalmente. Aponte a base URL para a Sheep e use seu token Sheep como `apiKey` ou `authToken`.

### TypeScript / Node

```typescript
import Anthropic from '@anthropic-ai/sdk'

const client = new Anthropic({
  baseURL: 'https://sheep.byfranke.com',
  apiKey: process.env.SHEEP_TOKEN,
})

const msg = await client.messages.create({
  model: 'hunter',
  max_tokens: 500,
  messages: [{ role: 'user', content: 'Olá!' }],
})

console.log(msg.content[0])
```

### Python

```python
import os
from anthropic import Anthropic

client = Anthropic(
    base_url="https://sheep.byfranke.com",
    api_key=os.environ["SHEEP_TOKEN"],
)

msg = client.messages.create(
    model="hunter",
    max_tokens=500,
    messages=[{"role": "user", "content": "Olá!"}],
)

print(msg.content[0].text)
```

## OpenClaude e outros agentes de terminal

Agentes como OpenClaude leem variáveis de ambiente padrão da Anthropic para descobrir provedor e credencial. Exporte estas duas variáveis e o agente passa a falar com a Sheep:

```bash
export ANTHROPIC_BASE_URL=https://sheep.byfranke.com
export ANTHROPIC_AUTH_TOKEN=shp_SEU_TOKEN
```

Alguns clientes preferem o nome `ANTHROPIC_API_KEY` em vez de `ANTHROPIC_AUTH_TOKEN`. Exporte os dois se houver dúvida sobre qual o cliente vai ler.

Use `hunter` como modelo padrão para agentes. Ele equilibra custo e qualidade no perfil de tarefa que um agente típico faz (ler, editar, perguntar de novo).

## Streaming

Envie `stream: true` no body para receber a resposta como Server-Sent Events. A sequência de eventos segue o padrão Anthropic:

```
message_start → content_block_start → content_block_delta+ →
content_block_stop → message_delta → message_stop
```

Cancelar a conexão TCP cancela o consumo de tokens upstream em poucas centenas de milissegundos. Tokens já gerados até o cancelamento permanecem cobrados; tokens não gerados não.

```bash
curl -N -X POST https://sheep.byfranke.com/v1/messages \
  -H "Authorization: Bearer shp_SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "hunter",
    "max_tokens": 500,
    "stream": true,
    "messages": [{"role":"user","content":"Olá!"}]
  }'
```

## Function calling (tools)

A Sheep aceita `tools` e `tool_choice` no mesmo formato da Anthropic. O modelo decide quando invocar; quando invoca, a resposta vem com `stop_reason: "tool_use"` e um bloco `tool_use` em `content`.

Limites de capacidade:

* Máximo de 16 tools por requisição.
* Máximo de 64 caracteres no `name` da tool. Apenas letras, dígitos, hífen e underscore. O `name` deve começar com letra ou underscore.
* Máximo de 2048 caracteres na `description`.
* Máximo de 32 propriedades top-level por `input_schema`.
* Até 4 invocações de tool por turno do modelo. Acima disso, as extras são descartadas em silêncio.

Exemplo:

```bash
curl -X POST https://sheep.byfranke.com/v1/messages \
  -H "Authorization: Bearer shp_SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "hunter",
    "max_tokens": 500,
    "messages": [{"role":"user","content":"Analise o hash 44d886..."}],
    "tools": [{
      "name": "lookup_ioc",
      "description": "Consulta reputação de IOC em fontes públicas",
      "input_schema": {
        "type": "object",
        "properties": {
          "ioc":  {"type": "string"},
          "kind": {"type": "string", "enum": ["ip","hash","domain","url"]}
        },
        "required": ["ioc","kind"]
      }
    }],
    "tool_choice": {"type": "auto"}
  }'
```

A Sheep nunca executa a tool. Apenas devolve o `tool_use`. Seu cliente executa e envia o resultado de volta como bloco `tool_result` na próxima mensagem.

## Diferenças em relação à Anthropic real

Estes são os pontos onde a Sheep diverge do contrato Anthropic. O cliente continua funcionando sem ajuste; o que muda é o comportamento detalhado.

* **Identificadores opacos.** `msg_<...>` e `toolu_<...>` são gerados pela Sheep e não correspondem aos identificadores que a Anthropic gera. O formato é compatível com o que SDKs esperam.
* **Modelos.** Os valores aceitos em `model` são apenas `scout`, `hunter`, `sage` e `auto`. Nomes da Anthropic (`claude-*`) são rejeitados com `400 invalid_model`.
* **`max_tokens` é clampado em silêncio.** Mínimo 100, máximo 2000. Valores fora da janela são ajustados sem erro. O default quando o campo é omitido é 1024.
* **`metadata.user_id` é aceito mas ignorado.** Não há isolamento upstream por sub-usuário no MVP.
* **`anthropic-version` e `anthropic-beta` são aceitos e ignorados.** A Sheep não versiona por header.
* **`system` aceita string simples ou array de blocos de texto.** O conteúdo é concatenado e tratado como instrução adicional. O Sheep tem seu próprio prompt de persona interna que prevalece sobre instruções de cliente que contradigam a identidade do Sheep.
* **`tools.input_schema` recebe validação básica.** A Sheep exige `type: "object"` e um dicionário `properties` válido. Esquemas JSON Schema mais complexos são aceitos sem validação profunda; comportamento depende do modelo.
* **Caching de prompt não é suportado.** Os campos `cache_creation_input_tokens` e `cache_read_input_tokens` em `usage` sempre retornam zero.
* **Vision (blocos `image`) não é suportado.** Enviar um bloco `image` retorna `400 unsupported_content_block`.
* **Computer use não é suportado.**
* **Não há endpoint Batch (`/v1/messages/batches`), Files API ou Embeddings.**

## Brand-opacity

A Sheep nunca se passa pela Anthropic. As respostas e erros mantêm a identidade Sheep, sem citar marcas de outros fornecedores de modelo. O contrato é Anthropic; a identidade é Sheep.

Se você precisar diferenciar nas respostas, três sinais ajudam:

* O cabeçalho `x-sheep-request-id` está presente em toda resposta.
* O cabeçalho `x-sheep-model-resolved` traz o tier Sheep que efetivamente respondeu.
* O cabeçalho `x-sheep-tokens-billed` informa quantos tokens Sheep foram debitados.

Esses cabeçalhos não conflitam com nenhum cliente Anthropic-compatible; SDKs ignoram cabeçalhos que não conhecem.

## Erros

O contrato de erro segue o formato Anthropic:

```json
{
  "type": "error",
  "error": {
    "type": "authentication_error",
    "message": "...",
    "code": "missing_or_invalid_token"
  }
}
```

Os tipos canônicos seguem o catálogo da Anthropic (`invalid_request_error`, `authentication_error`, `permission_error`, `not_found_error`, `request_too_large`, `rate_limit_error`, `api_error`, `overloaded_error`).

O campo `error.code` é uma extensão Sheep. SDKs Anthropic-compatible o ignoram, mas você pode usá-lo para tratamento programático mais fino. A lista completa dos códigos Sheep está em `errors.md`.

## Quotas e billing

Cada requisição em `/v1/messages` consome tokens da sua subscription da mesma forma que `/api/ai/ask`. O bucket é único: chamar um ou outro gasta no mesmo lugar.

A Sheep multiplica os tokens reais consumidos pelo upstream pelo multiplier do modelo escolhido. Tokens debitados na sua quota = tokens reais × multiplier do tier. Consulte `plans-and-quota.md` para a tabela completa.

O cabeçalho `x-sheep-tokens-billed` em cada resposta informa quantos tokens Sheep foram debitados naquela requisição.

## Limites operacionais

Estes são limites adicionais que a Sheep aplica em `/v1/messages` por razões de robustez.

* Corpo da requisição máximo: 5 MB.
* Conteúdo cumulativo das mensagens: 1 MB.
* Conteúdo por bloco individual: 256 KB.
* Lista `messages`: máximo 200 entradas.
* Última mensagem deve ser `role: "user"` ou conter pelo menos um bloco `tool_result`.

Consulte `rate-limits.md` para os limites de taxa por minuto.

## Próximos passos

* `endpoints/ask.md` documenta o caminho Sheep-native original.
* `models.md` lista o que cada tier de modelo entrega.
* `examples/python.md` e `examples/nodejs.md` trazem código pronto de integração.
