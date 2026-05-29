# Slash Commands

Esta página é a referência rápida de todos os slash commands do Sheep Bot. Comandos com profundidade própria são documentados em páginas dedicadas, em `features/`.

Comandos com limite mensal contam por usuário individual. O contador zera no primeiro dia de cada mês UTC. Membros Black Sheep, Sheep Plus, Sheep Pro e Sheep Pro Max não têm limite mensal nos comandos do bot.

## Inteligência e análise

### /ask

Conversação livre com o assistente de cibersegurança. Único campo no Discord: `question`. Aceita perguntas em texto natural em português ou inglês.

Acesso: free com limite mensal.

Documentação completa: `features/ask.md`.

### /analyze

Análise multi-fonte de um IOC. Único campo no Discord: `ioc`. Aceita IP, domínio, hash MD5/SHA-1/SHA-256 e URL. O tipo é detectado automaticamente. Retorna verdito categórico, score de risco, tags, recomendações e mapeamento MITRE ATT&CK em uma única resposta.

Acesso: free com limite mensal.

Documentação completa: `features/analyze.md`.

## Feeds

### /feeds

Configura os três feeds gratuitos em canais do servidor: Cybersecurity News, IOC Stream e CVE Alerts. Suporta as ações `enable`, `status`, `list`, `disable` e `delete`.

Acesso: administradores do servidor.

Documentação completa: `features/feeds.md`.

### /blackfeeds

Configura os feeds pagos em canais do servidor: Ransomware Monitor, Threat Intel Monitor, APT Infrastructure Monitor, Data Leak Monitor, ICS/SCADA Monitor e Vendor Research Monitor.

Acesso: administradores do servidor com membership Black Sheep ativa.

Documentação completa: `features/feeds.md`.

## Listener

### /listener

Ativa, desativa ou consulta o estado do Sheep Listener em um canal. Quando ativo, o bot responde a menções `@Sheep` ou a uma palavra-chave configurada. O consumo é cobrado da quota do administrador que ativou o Listener.

Acesso: administradores do servidor.

Documentação completa: `features/listener.md`.

### /listener-keyword

Configura uma palavra-chave que ativa o Sheep Listener além das menções `@Sheep`. Para remover a palavra, execute o comando com o campo vazio.

Acesso: administradores do servidor.

Documentação completa: `features/listener.md`.

## Membership e tokens

### /membership

Mostra o estado atual da sua membership no Sheep. Exibe plano vigente, data de expiração, tokens consumidos e restantes da Sheep API quando há plano contratado.

Acesso: público.

Argumentos: nenhum.

### /redeem

Ativa um código Black Sheep recebido por compra de gift card.

Acesso: público.

Argumentos:

* `code` (obrigatório). Código no formato `SB3M-XXXX-XXXX-XXXX` (3 meses), `SB6M-XXXX-XXXX-XXXX` (6 meses), `SB12-XXXX-XXXX-XXXX` (12 meses) ou `SB3D-XXXX-XXXX-XXXX` (trial de 3 dias).

### /trial

Solicita um trial gratuito de 3 dias da membership Black Sheep. Disponível uma única vez por conta.

Acesso: público.

Argumentos:

* `email` (obrigatório). E-mail para receber o código de ativação.

### /activate

Vincula sua conta Discord a uma assinatura paga (Sheep Plus, Sheep Pro, Sheep Pro Max) feita na Sheep Store. Após a vinculação, o `/membership` reflete o plano contratado e os comandos do bot deixam de impor o limite mensal de execuções. A quota de tokens da Sheep API do plano não é consumida pelos comandos do bot no Discord.

Acesso: público.

Argumentos:

* `email` (obrigatório). Mesmo e-mail usado no checkout na Sheep Store.

### /token

Emite, rotaciona ou consulta o token da Sheep API vinculado à sua conta. O token é entregue exclusivamente por e-mail.

Este é um dos caminhos disponíveis. Assinantes Sheep Plus, Sheep Pro e Sheep Pro Max também podem emitir o primeiro token diretamente pelo link enviado no e-mail de confirmação da assinatura, sem precisar abrir o Discord. Usuários Black Sheep e Black Sheep Trial usam este comando como caminho primário.

Acesso: requer membership ativa (Sheep Plus, Sheep Pro, Sheep Pro Max ou Black Sheep).

Argumentos: nenhum. O bot abre um fluxo interativo com confirmação por modal.

## Ranking

### /rank

Mostra seu rank atual, nível, XP acumulado e progresso até o próximo nível.

Acesso: público.

Argumentos: nenhum.

Documentação completa: `ranking.md`.

## Preferências

### /language

Define o idioma das respostas de sistema do bot para o seu usuário. A preferência é por conta e vale em todos os servidores onde você usa o Sheep Bot.

Acesso: público.

Argumentos:

* `language` (obrigatório). Valores aceitos: `pt`, `en`.

## Sistema e ajuda

### /help

Lista os comandos disponíveis para o seu nível de permissão. Adapta-se automaticamente a administradores, owners do bot e membros pagos.

Acesso: público.

Argumentos: nenhum.

### /about

Apresenta o Sheep, links oficiais e canais de suporte.

Acesso: público.

Argumentos: nenhum.

### /version

Mostra a versão atual do bot, codinome e principais novidades da release.

Acesso: público.

Argumentos:

* `detailed` (opcional). Quando `true`, exibe o histórico completo de versões em vez do resumo.

## Moderação

Comandos de moderação operam sobre o servidor Discord onde são executados. Não estão relacionados ao sistema de membership do Sheep.

### /ban

Bane um membro do servidor.

Acesso: administradores do servidor com permissão de banimento.

Argumentos:

* `user` (obrigatório). Usuário alvo.
* `reason` (opcional). Motivo do banimento.

### /kick

Expulsa um membro do servidor.

Acesso: administradores do servidor com permissão de expulsão.

Argumentos:

* `user` (obrigatório). Usuário alvo.
* `reason` (opcional).

### /mute

Aplica timeout em um membro do servidor.

Acesso: administradores do servidor com permissão de moderação.

Argumentos:

* `user` (obrigatório).
* `duration` (obrigatório). Duração do timeout.
* `reason` (opcional).

### /unmute

Remove timeout de um membro do servidor.

Acesso: administradores do servidor com permissão de moderação.

Argumentos:

* `user` (obrigatório).

### /clear

Apaga em lote mensagens recentes do canal atual.

Acesso: administradores do servidor com permissão de gerenciamento de mensagens.

Argumentos:

* `amount` (obrigatório). Número de mensagens a apagar. Limite: 100.

## Configuração de servidor

### /welcome

Gerencia mensagens de boas-vindas para novos membros do servidor.

Acesso: administradores do servidor.

Argumentos:

* `action` (obrigatório). Valores aceitos: `enable`, `status`, `disable`.

### /autorole

Configura atribuição automática de cargos a novos membros do servidor.

Acesso: administradores do servidor.

Argumentos: o comando abre um fluxo interativo com seleção dos cargos.

## Comandos com limite mensal

Os comandos abaixo contam por usuário no plano free. Cada um permite 10 execuções bem-sucedidas por mês:

* `/analyze`
* `/ask`

Comandos de moderação, configuração de servidor e administração não consomem limite. `/membership`, `/redeem`, `/trial`, `/activate`, `/token`, `/rank`, `/language`, `/help`, `/about`, `/version`, `/feeds`, `/blackfeeds`, `/listener` e `/listener-keyword` também são livres de limite mensal.

Membros Black Sheep, Sheep Plus, Sheep Pro e Sheep Pro Max não têm limite mensal de execuções nos comandos do bot. O uso de `/ask` e `/analyze` no Discord não consome a quota de tokens da Sheep API do plano. A quota do plano é consumida apenas em chamadas diretas à Sheep API e nas integrações que usam token pago (Sheep CLI e Sheep Web).
