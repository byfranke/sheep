# Changelog

Mudanças relevantes para integrações públicas. Entradas em ordem cronológica reversa.

Cada entrada lista escopo (`sheep-api`, `sheep-pulse`, `sheep-bot`, `sheep-cli`, `sheep-platform`, `docs`) e a mudança em uma linha.

## 2026-11-12

`sheep-platform`, `docs`. Sheep Agent, o modo agente do Ask da Sheep Platform: o botão **Agente**, ao lado do microfone e do anexo, faz a Sheep resolver a mensagem como uma tarefa, consultando por conta própria CVEs, MITRE ATT&CK, Ransomware Intel, feeds e a base de indicadores conhecidos e mostrando cada passo. Usa o Sage 120B, no Sheep Pro e no Sheep Pro Max. Começa desligado, vale por conversa, tem limite de 30 passos e 200 mil tokens por tarefa e pode ser parado a qualquer momento. Também entrega o resultado em arquivo (PDF, HTML, Markdown, CSV, JSON ou texto) para baixar na conversa. Também entrou na comparação de planos (`sheep-api/plans-and-quota.md`). Guia em `sheep-platform/README.md`.

## 2026-11-12

`sheep-cli`, `docs`. Sheep CLI 1.4.0: o agente consulta a inteligência da Sheep como ferramenta (CVE, MITRE ATT&CK, Ransomware Intel, feeds e relatório DFIR), roda em scripts e CI com `sheep-cli -p "<tarefa>"`, ganha o modo de permissão `ask` (mostra e pergunta antes de cada alteração), lê páginas web com confirmação por site e, no Windows, roda os comandos no PowerShell. Também se apresenta como agente ao abrir, começa a tarefa sem saudação e não para mais quando o modelo escreve a entrada de uma ferramenta de forma ilegível. Segurança: todo comando proposto pelo agente pede confirmação, a não ser que só leia dentro da pasta ou bata com uma regra salva, e regras nunca cobrem comandos encadeados. Arquivos ocultos e alterações feitas a partir da pasta do usuário sempre pedem confirmação, e `.git` e as configurações do CLI nunca são alterados. Guia em `sheep-cli/README.md`.

## 2026-11-12

`sheep-cli`, `docs`. Sheep CLI 1.3.0: o `sheep-cli` vira agente. Todo pedido pode ser executado no computador (arquivos, código, comandos, investigação), com a inteligência de ameaças da Sheep por trás. Novos: instruções do projeto em `SHEEP.md` ou `AGENTS.md`, lista de tarefas visível, leitura de arquivos grandes em partes, consulta de indicadores à Sheep, `/undo` para devolver os arquivos da última tarefa e `/agent` para ligar, desligar e ajustar o limite de passos e de tokens por tarefa. Senhas, chaves e tokens são mascarados antes de qualquer envio, e o Sage 120B é o padrão nos planos Sheep Pro e Sheep Pro Max. Guia em `sheep-cli/README.md`.

## 2026-11-12

`sheep-cli`, `docs`. Instaladores do Sheep CLI: rodar o comando de instalação de novo agora atualiza a instalação e mantém o token e as sessões. Se a versão instalada já for a mais recente, o instalador avisa e não baixa nada, e binário e `SHA256SUMS` vêm sempre da mesma versão. No Windows, erros não fecham mais a janela do PowerShell e a atualização funciona com o `sheep-cli` aberto. Sheep CLI 1.2.5: aviso ao abrir quando há versão nova (no máximo uma vez por dia, desligável com `SHEEP_CLI_NO_UPDATE_CHECK=1`), `/update` consulta a versão mais recente na hora, leitura do token pela variável `SHEEP_API_TOKEN`, parcela semanal e tokens bônus no `/profile` e mensagem própria quando a parcela da semana acaba. Guia em `sheep-cli/README.md`.

## 2026-11-11

`sheep-pulse`, `sheep-platform`, `docs`. Envio automático do Pulse na Sheep Platform: a engrenagem do Pulse ganhou a opção de gerar e enviar o Pulse sozinho, todos os dias, a cada 3 dias ou uma vez por semana. Vale em todos os planos pagos, dentro do limite de Pulses de cada plano. No teste aparece trancado, e a API responde `403 auto_send_not_in_plan`. A página de Planos ganhou a tabela "Compare os planos".

## 2026-11-11

`sheep-pulse`, `sheep-platform`, `docs`. Novos limites do Pulse: 1 por dia no Sheep Plus e no Black Sheep, 30 por dia no Sheep Pro e 50 por dia no Sheep Pro Max. O teste continua com 1 Pulse no total. No período de teste, o console passa a mostrar trancados, com o convite para assinar, os cartões de convites e de gift card como tokens bônus. Documentação revisada: comparação dos planos em `sheep-api/plans-and-quota.md`, códigos de erro `quota_exhausted` e `model_not_in_plan`, teste só com o modelo `auto`, gift cards de 3, 6 ou 12 meses resgatados no site ou no Discord, emissão do token pela Sheep Platform e Pulse dentro da Sheep Platform.

## 2026-11-10

`sheep-platform`, `docs`. Tour de primeiro acesso no console: um passo a passo curto mostra onde fica cada coisa. Aparece uma vez por conta, pode ser pulado e revisto em Conta > Preferências.

## 2026-11-10

`sheep-platform`, `docs`. Busca rápida no console: Ctrl K (ou a lupa no topo) leva a qualquer módulo, abre relatórios DFIR, briefings, resumos do dia e conversas salvos e começa uma análise ou uma pergunta. O botão do plano abre o menu da conta, com o uso do período e atalhos. Relatórios DFIR e resumos do dia salvos abrem numa janela de leitura por cima da tela, e as opções do Analyze abrem num balão.

## 2026-11-10

`sheep-platform`, `docs`. Notificações no console: o sino no canto superior avisa relatório pronto, mudanças no Radar, Pulse automático, bônus de convite, uso de 80%, 95% e 100% dos tokens, parcela da semana e fim do teste ou do plano. A aba Briefing do Pulse ganhou o mesmo desenho do Radar, com o editor de perfil numa janela. Política de privacidade atualizada. Todo Pulse, relatório DFIR e resumo do dia pronto entra no sino, e o aviso do Pulse abre aquele briefing. O sino também traz avisos da equipe Sheep sobre novidades. O Analyze ganhou um topo no padrão do Radar, com o passo a passo de como funciona.

## 2026-11-09

`sheep-platform`, `docs`. Resumo do dia na aba Feeds: a Sheep AI lê as últimas 24 horas dos feeds e organiza os destaques (vulnerabilidades, ransomware, ameaças, indicadores e o que fazer hoje). Consome tokens do plano, fica 7 dias em Resumos salvos e pode ser baixado em PDF ou Markdown. Política de privacidade atualizada com esse prazo.

## 2026-11-09

`sheep-platform`, `sheep-api`, `docs`. Gift card como tokens bônus: no Sheep Pro e no Sheep Pro Max, Conta > Plano e uso converte um gift card Black Sheep em tokens extras do período atual (500 mil, 1 milhão ou 2 milhões), mostrados à parte e vencendo com o período, mediante aceite de que o código não dá acesso Black Sheep.

## 2026-11-09

`sheep-api`, `sheep-platform`, `docs`. Ritmo semanal nos planos de entrada (Sheep Plus e Black Sheep): a cota do período é liberada em parcelas semanais; ao chegar à parcela, a API responde `402 weekly_limit_reached` e a Platform pergunta se o cliente quer liberar o restante do período (uma vez por período) ou fazer upgrade com o cupom `UPGRADE40`. E-mail de aviso a 95% da cota, uma vez por período. `GET /api/profile` expõe o estado em `pacing`.

## 2026-11-09

`docs`. Site da Sheep: captura da newsletter no fim da página inicial e a página `/pages/newsletter` no mesmo desenho das demais páginas, com animação.

## 2026-11-09

`sheep-platform`. Recursos dos planos superiores agora aparecem na Platform, desativados, com o que cada plano libera: os modelos Scout, Hunter e Sage no seletor do Ask e no modelo padrão das Preferências, a Voz Sheep no período de teste e um contador de Pulses com o limite diário do plano seguinte.

## 2026-11-09

`sheep-pulse`, `docs`. Radar no Pulse: monitoramento da exposição dos domínios da empresa, com nota de A a F só com dados públicos, nova análise a cada 24 horas, relatório completo e aviso por e-mail quando a nota piora. O domínio precisa ser o do e-mail da conta ou ser autorizado por um e-mail do próprio domínio. Detalhes em `sheep-pulse/radar.md`. Política de privacidade atualizada.

## 2026-11-09

`sheep-platform`. Integrações ganha a aba Sheep CLI, ao lado de Sheep MCP e Sheep API: o que a CLI é, instalação em um comando para Linux, macOS e Windows, como passar o token, as outras CLIs da Sheep e os links para o site, o GitHub e o guia.

## 2026-11-09

`docs`. Os três projetos de exemplo da Sheep API (`sheep-ask-cli`, `sheep-analyze-cli`, `sheep-feeds-cli`, código aberto em Python) ganharam destaque como ponto de partida na página da Sheep API, na aba Integrações da Platform e no manual da API.

## 2026-11-09

`sheep-api`, `docs`. Sheep MCP no Gemini: o app do Gemini (gemini.google.com > Conectores > Personalizado) conecta à Sheep com a conta Sheep, como o Claude e o ChatGPT. Passo a passo na página do MCP, em Integrações e no guia.

## 2026-11-09

`sheep-platform`, `docs`. Convites para todos os planos pagos, com prêmio em tokens bônus: 15.000 tokens quando o convidado ativa o trial e 150.000 quando assina um plano pago (7 dias após o primeiro pagamento), até 5 bônus de trial por mês e 1.500.000 tokens por ano. O bônus entra no período de cobrança em curso do plano e aparece no card Tokens bônus da Conta. Substitui os dias de bônus da primeira versão, que valia só para o Black Sheep ativado pelo site.

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
