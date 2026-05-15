# Changelog

Mudanças relevantes para integrações públicas. Entradas em ordem cronológica reversa.

Cada entrada lista escopo (`sheep-api`, `sheep-pulse`, `sheep-bot`, `sheep-cli`, `docs`) e a mudança em uma linha.

## 2026-05-13

`docs`. Reescrita completa da documentação pública. Conteúdo reorganizado em árvore por produto: `sheep-bot/`, `sheep-api/`, `sheep-pulse/` e `sheep-cli/`. Os recursos principais do Sheep Bot ganharam páginas próprias em `sheep-bot/features/`: Sheep Ask, Sheep Analyze, Sheep Feeds e Sheep Listener. Cada endpoint da API ganhou página própria em `sheep-api/endpoints/`. Exemplos consolidados em `sheep-api/examples/` (curl, Python, Node.js, PowerShell). Workflows n8n em `sheep-api/integrations/n8n-examples/`.

`sheep-api`. Contrato de resposta documentado conforme o shape vigente em produção: campos `success`, `response`, `served_by`, `tokens_used`, `usage`, `requested_model`, `model`, `timestamp`, `error`. Erros agora seguem o padrão `detail.error` e `detail.message`.

## 2026-05-12

`sheep-bot`. Lançamento do Sheep Listener, presença ambiente do Sheep em canais Discord. Comandos `/listener` e `/listener-keyword`. Limites uniformes: 5 respostas por minuto, 100 por dia por canal, 3 canais ativos por administrador.

## 2026-05-11

`sheep-pulse`. Lançamento do Sheep Pulse, briefings de CTI sob demanda com entrega por e-mail e webhook HTTPS. Limites por plano: trial 1 vitalício e 1 por dia; Black Sheep 5 por dia; Pro 10 por dia; Pro Max 30 por dia; Enterprise 100 por dia.

## 2026-05-07

Sheep 4 v4.2.1 estável. Codinome "Sheep Pulse".

`sheep-bot`. Comandos `/workflow`, `/incident_response`, `/portscan` e `/ipreport` foram removidos por baixa adesão. As capacidades dessas operações foram consolidadas em `/analyze` e `/ask`.

`sheep-bot`. Os comandos standalone `/virustotal`, `/urlscan` e `/shodan` foram substituídos pelo `/analyze`, que consolida múltiplas fontes de reputação numa única operação. O comportamento, o argumento e o formato de retorno do `/analyze` cobrem todos os casos de uso anteriores.

`sheep-bot`. Tour de onboarding adicionado. Novos usuários recebem orientação inline ao executar o primeiro slash command.

`sheep-bot`. Plano gratuito mantém acesso aos feeds essenciais via Discord: notícias de segurança, fluxo de IOCs e alertas CVE.

`sheep-bot`. Feeds pagos passam a exigir membership Black Sheep ativa. Gestão via `/blackfeeds`.

`sheep-api`. Fundação dos tiers de modelo Scout, Hunter e Sage publicada. O parâmetro `model` agora aceita os identificadores estáveis `auto`, `scout`, `hunter` e `sage` em `/api/ai/ask` e `/api/ai/analyze`.

## 2026-05-02

`sheep-api`. Padronização do header de autenticação. Todas as chamadas autenticadas usam exclusivamente `X-Sheep-Token`. Formato fixo `shp_<32 caracteres hexadecimais>`. Entrega do token exclusivamente por e-mail, sem exposição no Discord.

`sheep-api`. Tokens deixaram de carregar identificação de plano no prefixo. Todos seguem o mesmo formato. O plano é resolvido server-side e exposto em `GET /api/profile`.

## 2026-04-22

Sheep 4 v4.1.0 estável. Codinome "Sheep Ask".

`sheep-bot`. Rebranding para Sheep Ask. Interface unificada em inglês profissional como padrão, com suporte ao português via `/language`.

`sheep-bot`. Assistente de IA para cibersegurança aprimorado. Análises e respostas com maior consistência em consultas multi-IOC.

`sheep-bot`. `/help` reformulado com auto-detecção de permissões e foco em descoberta.

## 2025-12-03

Sheep 4 v4.0.0 estável. Codinome "Sheep 4 - CTI AI Platform".

`sheep-bot`. Lançamento da plataforma Sheep 4 de Cyber Threat Intelligence assistida por IA. Substitui a linha 3.x.

`sheep-bot`. Dashboard administrativo redesenhado.

## 2025-08-25

Sheep 3 v3.0.0 estável. Codinome "Black Sheep Revolution". Status atual: legado.

`sheep-bot`. Reescrita modular do bot. A base passou a separar responsabilidades em módulos por área (administração, membros, segurança, feeds, utilitários), abrindo caminho para a evolução posterior em Sheep 4.

`sheep-bot`. Sistema de feeds RSS automatizado com cobertura ampla de fontes públicas de cibersegurança. Configuração por canal via `/rssfeed`. Posts deduplicados, sem repetir o mesmo item entre execuções.

`sheep-bot`. Sistema de membership Black Sheep introduzido. Resgate por código via `/redeem`. Consulta de status via `/subscription`. Diferenciação clara entre níveis gratuito e premium.

`sheep-bot`. Rate limiting individual por usuário e por comando. Garante uso sustentável das ferramentas no plano gratuito sem afetar membros premium.

## 2024-08-10

Sheep 2 v2.0.0 estável. Codinome "Security Foundation". Status atual: depreciado.

`sheep-bot`. Migração completa para slash commands (`/`). Padroniza a interação com o bot dentro do Discord moderno.

`sheep-bot`. Primeira geração de comandos de cibersegurança nativos. Cobertura inicial de checagem de reputação de IP, análise de hash, varredura de URL e busca de host por palavra-chave.

`sheep-bot`. Sistema de mensagens de boas-vindas e atribuição automática de cargos para novos membros do servidor.

## 2024-01-15

Sheep 1 v1.0.0 estável. Codinome "First Steps". Status atual: arquivado.

`sheep-bot`. Lançamento original do bot. Comandos básicos de moderação (`!mute`, `!unmute`, `!kick`, `!ban`, `!ping`, `!help`) com prefixo de texto.

`sheep-bot`. Sistema simples de autorização por lista de usuários. Foundation para o sistema de membership que viria nas versões seguintes.

---

Versões anteriores a 4.0.0 estão fora de suporte. Não há migração automática para clientes da linha 3.x, 2.x ou 1.x. Clientes em produção devem operar exclusivamente na linha 4.x.
