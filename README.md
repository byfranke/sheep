# Sheep Documentation

Documentação pública do ecossistema Sheep.

Sheep é uma plataforma de Cyber Threat Intelligence assistida por IA. A plataforma reúne uma API HTTP, ferramentas de linha de comando, um portal de briefings sob demanda e um bot que opera dentro do Discord.

## Navegação

A documentação está dividida por produto. Comece pela página que combina com o seu objetivo.

`getting-started.md`
: Primeiro contato. Como criar uma conta, emitir um token e fazer a primeira chamada à API. Comece por aqui se você nunca usou o Sheep.

`sheep-bot/`
: Bot Discord do Sheep. Lista completa de slash commands, configuração de feeds, Sheep Listener, ranking e membership pelo Discord.

`sheep-api/`
: Manual da Sheep API. Autenticação, planos, modelos, endpoints, limites e exemplos de integração. Use quando for construir integrações com SOC, SOAR, SIEM, scripts internos ou produtos de terceiros.

`sheep-pulse/`
: Briefings de CTI sob demanda. Como gerar um Pulse pelo portal, configurar perfil e receber por e-mail ou webhook.

`sheep-cli/`
: Ferramentas de linha de comando oficiais do Sheep para terminais e pipelines locais.

`CHANGELOG.md`
: Mudanças relevantes para integrações públicas, organizadas por data e escopo.

## Convenções desta documentação

Todos os blocos de código usam dados fictícios. Tokens, e-mails e identificadores não correspondem a contas reais.

Endpoints sempre aparecem com a URL absoluta. A base pública é `https://sheep.byfranke.com`. Não há host alternativo, espelho ou ambiente de sandbox neste momento.

A documentação descreve apenas a superfície pública. Endpoints administrativos, internos e operações fora deste manual não são suportados para uso externo.

## Suporte

Comunidade pública para discussão e dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais, incidentes ou pedidos formais: `https://byfranke.com/#Contact`.

## Licença

Consulte `LICENSE.txt`.
