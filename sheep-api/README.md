# Sheep API

A Sheep API é a interface HTTP do ecossistema Sheep. Ela expõe consultas de IA, análise de Indicadores de Comprometimento (IOCs) e leitura de feeds curados de Threat Intelligence para integração programática.

## Para quem é

A Sheep API atende três tipos de uso:

* Pipelines de SOC que precisam enriquecer e narrar alertas antes da triagem humana.
* Plataformas SOAR e workflows automatizados que consultam reputação multi-fonte e mapeiam observáveis para o framework MITRE ATT&CK.
* Aplicações internas e ferramentas de linha de comando que dão acesso conversacional à IA do Sheep para analistas.

A API não oferece operações administrativas, gestão de assinaturas ou backoffice. Esses fluxos pertencem ao bot do Discord e à Sheep Store.

## Base

Endpoint base: `https://sheep.byfranke.com`

Todas as requisições devem usar HTTPS. Não há endpoint HTTP em texto puro.

## Dois caminhos de integração

A Sheep API expõe duas superfícies em paralelo. Ambas usam o mesmo token, a mesma quota e o mesmo billing. Você escolhe a que combina com a sua integração.

* **Sheep-native** (`/api/ai/ask`, `/api/ai/analyze`, `/api/feeds/*`). Formato proprietário, mais direto. Recomendado para integrações novas em scripts, n8n, SOC pipelines e ferramentas locais. Documentado em `endpoints/`.
* **Anthropic-compatible** (`POST /v1/messages`, `GET /v1/models`). Fala o mesmo protocolo wire da Anthropic Messages API. Recomendado quando você já tem um cliente escrito para esse protocolo (SDKs oficiais, OpenClaude, Cline, Cursor, Aider, plugins de editor). Documentado em `anthropic-compatibility.md`.

Os dois caminhos convivem indefinidamente. Não há plano de descontinuar o caminho Sheep-native.

Para usar a Sheep de dentro do seu próprio assistente de IA (Claude Code, Claude Desktop, Cursor, VS Code, n8n), conecte o **Sheep MCP** em `https://sheep.byfranke.com/mcp`. Ele usa o mesmo token e a mesma quota. Documentado em `integrations/mcp.md`.

## Projetos de exemplo (código aberto)

Três ferramentas de linha de comando, em Python e com o código aberto, mostram a Sheep API em uso real. Elas não substituem os exemplos deste manual: são um ponto de partida para estudar as possibilidades, copiar o que interessa e construir a sua própria integração.

* `https://github.com/byfranke/sheep-ask-cli`: uma pergunta, uma resposta, no terminal. O mínimo para chamar `POST /api/ai/ask` e tratar resposta e erros.
* `https://github.com/byfranke/sheep-analyze-cli`: análise de IOC (IP, domínio, hash, URL, CVE) com a resposta estruturada de `POST /api/ai/analyze`. Base para integrar com SIEM e SOAR.
* `https://github.com/byfranke/sheep-feeds-cli`: leitura de `GET /api/feeds/*` em JSON, com filtros, paginação e um motor de regras local que avisa quando um item combina.

Cada repositório tem o README com instalação, parâmetros e exemplos. Visão geral das CLIs em `../sheep-cli/README.md`.

## Como ler este manual

Comece pelos conceitos. Eles definem o vocabulário usado em todos os endpoints.

* `authentication.md` apresenta o header de autenticação e o ciclo de vida do token.
* `plans-and-quota.md` explica como o consumo é medido em tokens Sheep e como cada plano define seu teto mensal.
* `models.md` descreve os tiers de modelo disponíveis e quando usar cada um.
* `rate-limits.md` define os limites de taxa por endpoint.
* `errors.md` documenta o contrato de erro e a lista de códigos.
* `best-practices.md` consolida recomendações operacionais para produção.

Depois, consulte o endpoint que você precisa.

* `endpoints/ask.md` para conversação livre com a IA pelo caminho Sheep-native.
* `endpoints/analyze.md` para análise estruturada de um IOC isolado.
* `endpoints/profile.md` para verificar plano, saldo e modelos liberados.
* `endpoints/status.md` para health check público.
* `endpoints/models.md` para descobrir os modelos disponíveis.
* `endpoints/feeds.md` para consumir feeds de Threat Intelligence.
* `anthropic-compatibility.md` para o caminho Anthropic-compatible (`/v1/messages`, `/v1/models`, SDKs oficiais, OpenClaude).

Quando precisar de código pronto, vá para os exemplos.

* `examples/curl.md`, `examples/python.md`, `examples/nodejs.md` e `examples/powershell.md`.
* `integrations/n8n.md` traz workflows prontos para automação.
* `integrations/mcp.md` mostra como conectar o Sheep MCP ao seu assistente de IA e lista as ferramentas.

## Princípios de contrato

Estes princípios se aplicam a todos os endpoints. Eles definem o que muda e o que permanece estável.

Estabilidade de campos. Nomes de campos em respostas são estáveis. Novos campos podem aparecer; campos existentes não são removidos sem aviso prévio.

Códigos de erro como contrato. Clientes devem ramificar comportamento por `error.code`, não por mensagens humanas. Mensagens podem mudar entre versões; códigos só mudam com aviso prévio.

Aviso prévio. Mudanças que afetam código cliente recebem aviso de pelo menos trinta dias na comunidade do Discord e no `CHANGELOG.md` deste manual.

Manutenção sem janela fixa. Atualizações são aplicadas sem interrupção observável. Não há janela de manutenção pré-anunciada.
