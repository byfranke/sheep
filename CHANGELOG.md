# Changelog

Mudanças relevantes para integrações públicas. Entradas em ordem cronológica reversa.

Cada entrada lista escopo (`sheep-api`, `sheep-pulse`, `sheep-bot`, `sheep-cli`, `sheep-platform`, `docs`) e a mudança em uma linha.

## 2026-11-09

`sheep-api`. Sheep MCP: três ferramentas novas. `sheep_analyze_batch` analisa até 25 indicadores de uma vez (lista ou STIX 2.1, MISP, CSV e texto colados, com veredito por indicador), `sheep_conversations` e `sheep_conversation` deixam o assistente listar e ler as conversas do Ask da própria conta para continuar um assunto começado na Platform.

## 2026-11-09

`sheep-api`, `docs`. Guia do Sheep MCP: passos atualizados para conectar o ChatGPT (chatgpt.com/plugins > Add custom MCP server). Política de privacidade: registros de acesso guardados por 6 meses (Marco Civil, art. 15).

## 2026-11-09

`sheep-platform`. Modo conversa do Ask: quando o navegador não oferece reconhecimento de voz, a Sheep transcreve a fala (com aviso e confirmação na primeira vez, sem custo em tokens, áudio não guardado). A saudação do Ask passa a variar com o nome, a área e a hora do dia.

## 2026-11-09

`sheep-platform`, `docs`. Importação de listas de indicadores no Analyze: STIX 2.1, exportação do MISP (JSON ou CSV), CSV ou texto, lidos no navegador; os indicadores selecionados são analisados um a um e o resultado sai em CSV.

## 2026-11-09

`sheep-platform`, `docs`. Triagem local de arquivos no Ask: executáveis, ZIP, documentos Office, PDF e atalhos são analisados no navegador (hash, tipo real, macro, JavaScript, modelo remoto, executável no pacote, extensão dupla, entropia) e só o resumo é enviado; o arquivo nunca sai do computador. Hash sem registro não é veredito de arquivo limpo.

## 2026-11-09

`sheep-platform`, `docs`. Ciclo de vida do conteúdo: conversas do Ask, briefings do Pulse e relatórios DFIR ficam 30 dias ativos desde o último uso e mais 30 dias na Lixeira de cada módulo (restaurar ou excluir na hora); apagar manda para a Lixeira; "Apagar todas" e "Esvaziar lixeira" no Ask. Depois de 60 dias o item sai do console e fica cifrado por 6 meses só para fins legais, com chave que a plataforma não abre. Carência: nada vai para a Lixeira sozinho antes de 09/12/2026. Política de privacidade atualizada.

## 2026-11-08

`sheep-platform`, `docs`. Imagens no Ask: anexe, arraste ou cole uma captura de tela junto com a pergunta; a Sheep extrai o texto e a descrição e responde com o contexto de inteligência habitual. A imagem não é guardada, só o texto extraído entra na conversa; a leitura é cobrada em tokens com a resposta. Setas para cima e para baixo no campo percorrem as perguntas já enviadas.

## 2026-11-08

`sheep-platform`, `docs`. Leitura em voz alta das respostas do Ask. Botão de alto-falante em cada resposta, lido pela voz do próprio aparelho, sem custo. Opcionalmente, o **Áudio aprimorado (Voz Sheep)** em Conta > Preferências gera o áudio com voz de IA de qualidade de estúdio, descontado dos tokens da cota (preço por caractere, explicado ao ativar a opção e mostrado em cada áudio), com o áudio guardado por 7 dias para ouvir de novo sem novo custo. Indisponível no período de teste. Modo conversa: botão de microfone no Ask (reconhecimento de voz do navegador, sem custo), resposta falada frase a frase durante a geração e microfone reaberto ao final. Política de privacidade atualizada.

## 2026-11-08

`sheep-bot`, `docs`. Proteção contra golpe de contas invadidas em todos os servidores onde o Sheep Bot está. O bot apaga o golpe das quatro imagens do cassino de cripto, aplica castigo de 7 dias sem expulsar nem banir, envia ao membro o passo a passo para recuperar a conta e avisa o dono do servidor. Novo comando de mensagem `Golpe: conta invadida` (`Scam: hijacked account`) para a equipe tratar um golpe que passou. Detalhes em `sheep-bot/features/scam-guard.md`.

## 2026-06-15

`sheep-platform`, `docs`. Console otimizado para celular. Em telas estreitas, a navegação passa a usar uma barra inferior fixa com os módulos de uso mais frequente e um botão `Menu` para os demais módulos e para sair. O conteúdo se ajusta à largura da tela e a lista de conversas do módulo Ask passa a ser acessível no celular. Sem mudança no uso pelo computador.

## 2026-06-08

`sheep-platform`, `docs`. Novos módulos no console: Recursos (hub de ferramentas e referências de CTI), Ransomware Intel (vítimas e grupos com filtros por grupo, setor e severidade) e DFIR (relatório de resposta a incidente com análise de IOCs, mapeamento MITRE ATT&CK e recomendações, exportável em PDF). Analyze e Pulse também passam a exportar em PDF. Adicionada a verificação em duas etapas (2FA) opcional, configurável no módulo Conta, com códigos de backup.

## 2026-06-05

`sheep-platform`, `docs`. Lançamento do Sheep Platform, o console web unificado da Sheep. Acesso único por e-mail a partir de `https://sheep.byfranke.com/login`, com link de uso único e sessão de 24 horas. Reúne em um só painel os módulos Dashboard, Feeds, Ask, Analyze, Pulse e Conta. O histórico de Ask e de Pulse é compartilhado com as superfícies equivalentes da plataforma. A disponibilidade de cada módulo segue o plano.

## 2026-05-27

`docs`, `sheep-api`, `sheep-bot`, `sheep-pulse`. Renomeação dos planos pagos. O plano antigo "Sheep Pro" passou a chamar **Sheep Plus**. O antigo "Sheep Pro Max" passou a chamar **Sheep Pro**. O antigo "Sheep Enterprise" passou a chamar **Sheep Pro Max**.

## 2026-05-13

`docs`. Reescrita completa da documentação pública. Conteúdo reorganizado em árvore por produto: `sheep-bot/`, `sheep-api/`, `sheep-pulse/` e `sheep-cli/`. Os recursos principais do Sheep Bot ganharam páginas próprias em `sheep-bot/features/`: Sheep Ask, Sheep Analyze, Sheep Feeds e Sheep Listener. Cada endpoint da API ganhou página própria em `sheep-api/endpoints/`. Exemplos consolidados em `sheep-api/examples/` (curl, Python, Node.js, PowerShell). Workflows n8n em `sheep-api/integrations/n8n-examples/`.

`sheep-api`. Contrato de resposta documentado conforme o shape vigente em produção: campos `success`, `response`, `served_by`, `tokens_used`, `usage`, `requested_model`, `model`, `timestamp`, `error`. Erros agora seguem o padrão `detail.error` e `detail.message`.

## 2026-05-12

`sheep-bot`. Lançamento do Sheep Listener, presença ambiente do Sheep em canais Discord. Comandos `/listener` e `/listener-keyword`. Limites uniformes: 5 respostas por minuto, 100 por dia por canal, 3 canais ativos por administrador.

## 2026-05-11

`sheep-pulse`. Lançamento do Sheep Pulse, briefings de CTI sob demanda com entrega por e-mail e webhook HTTPS. Limites por plano: trial 1 vitalício e 1 por dia; Black Sheep 5 por dia; Sheep Plus 10 por dia; Sheep Pro 30 por dia; Sheep Pro Max 100 por dia.

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
