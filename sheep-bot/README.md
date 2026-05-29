# Sheep Bot

Sheep Bot é o bot Discord oficial do ecossistema Sheep. Ele entrega slash commands para análise de IOCs, conversação com a IA de cibersegurança, gestão de membership, feeds de Threat Intelligence e moderação de servidor.

A versão estável em produção é a 4.2.1, codinome "Sheep Pulse".

## Para quem é

Sheep Bot atende três perfis dentro do Discord:

* Analistas e profissionais de segurança que querem operar IOCs, hashes, IPs, URLs e CVEs diretamente do chat.
* Administradores de comunidades de cibersegurança que querem feeds de Threat Intelligence publicados automaticamente em canais do servidor.
* Membros pagos que usam o bot como porta de entrada para a Sheep API, briefings Pulse e feeds premium.

## Como instalar

Adicione o bot ao seu servidor pelo link oficial de instalação:

```
https://sheep.byfranke.com/addbot
```

O usuário que adiciona o bot precisa ter permissão de gerenciamento de servidor no Discord. Após a instalação, todos os slash commands ficam disponíveis para os membros conforme as regras de acesso descritas em `commands.md`.

A comunidade pública do Sheep, com suporte técnico, está em `https://sheep.byfranke.com/discord`. Entrar na comunidade é opcional para usar o bot.

## Como ler este manual

Comece pelos recursos principais. Cada recurso tem página própria em `features/` com explicação do que faz, quem pode usar, exemplos e troubleshooting.

`features/ask.md`
: Sheep Ask. Conversação livre com a IA de cibersegurança. Aceita perguntas em texto natural com escolha de tier de modelo.

`features/analyze.md`
: Sheep Analyze. Análise estruturada de IOC, CVE ou família de malware com saída padronizada para triagem rápida.

`features/feeds.md`
: Sheep Feeds. Configuração de feeds de Threat Intelligence em canais dedicados do servidor. Cobre feeds gratuitos e pagos.

`features/listener.md`
: Sheep Listener. Presença ambiente do Sheep em canais de discussão. Membros conversam com o bot mencionando o nome ou usando palavra-chave.

Depois, complementos:

`commands.md`
: Referência rápida de todos os 28 slash commands ativos. Inclui moderação, configuração de servidor e comandos triviais.

`ranking.md`
: Sistema de progressão por XP. Como funcionam os ranks e como subir de nível usando os comandos de análise.

`membership.md`
: Como ativar Black Sheep via gift card, vincular planos pagos da Sheep Store, conferir status de membership e solicitar trial.

## Planos e acesso

O bot diferencia três níveis de acesso:

* **Free**. Acesso a comandos básicos com limite mensal por comando (10 usos por mês em `/ask` e `/analyze`).
* **Black Sheep**. Gift card mensal, semestral ou anual. Remove limites mensais nos comandos do bot e libera feeds pagos.
* **Sheep Plus, Sheep Pro, Sheep Pro Max**. Planos contratados na Sheep Store. Cobrem o uso do bot pelo Discord e adicionam acesso à Sheep API e ao Sheep Pulse.

Os planos contratados pela Sheep Store também aparecem dentro do bot através de `/membership` quando o e-mail do Discord está vinculado à conta. O processo de vinculação é feito por `/activate`.

## Convenções desta documentação

Todos os exemplos de comando usam dados fictícios. Tokens, IDs de usuário e endereços nos exemplos não correspondem a contas reais.

Comandos privilegiados aparecem marcados com a permissão necessária (administrador do servidor, owner do bot, membership ativa). Tentativas de uso fora do nível recebem mensagem clara do bot e não consomem cota.

## Suporte

Comunidade pública e suporte técnico: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
