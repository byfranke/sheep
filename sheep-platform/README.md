# Sheep Platform

Sheep Platform é o console web da Sheep. Um único acesso reúne os produtos da plataforma em uma só tela: feeds de inteligência, chat de cibersegurança, análise de indicadores, briefings sob demanda e a gestão da sua conta. Em vez de abrir portais separados, você navega entre os módulos por um menu de navegação, com um login só.

Use o console quando preferir operar pelo navegador, sem terminal nem integração própria. O histórico é compartilhado com os demais produtos. As conversas e os briefings gerados aqui aparecem também nas superfícies equivalentes da plataforma, e vice-versa.

Endereço do console: `https://sheep.byfranke.com/app`.

## Pré-requisitos

* Conta Sheep com assinatura ativa: Sheep Plus, Sheep Pro, Sheep Pro Max, Black Sheep ou Black Sheep Trial.
* E-mail vinculado à sua conta. O mesmo e-mail usado para receber o token da API.

O uso gratuito do Sheep Bot no Discord não dá acesso ao console. Todos os módulos abrem em qualquer plano ativo, inclusive no teste. O que muda entre os planos está em "O que muda entre os planos", mais abaixo.

## Como acessar

1. Acesse `https://sheep.byfranke.com/login`.
2. Informe o e-mail vinculado à sua conta e clique em "Acessar".
3. Você recebe um link de acesso por e-mail. Abra o e-mail e clique no link.
4. O console abre em `https://sheep.byfranke.com/app`.

Não há senha. Toda autenticação acontece pelo e-mail vinculado. O link de acesso é de uso único e expira após alguns minutos. A sessão expira depois de 3 dias sem uso e dura no máximo 7 dias desde o login.

Se você ativou a verificação em duas etapas (2FA), após clicar no link a plataforma pede um código de 6 dígitos do seu app autenticador para concluir o login.

Por segurança, a tela de acesso responde da mesma forma para qualquer e-mail informado. Receber o e-mail confirma que o endereço está vinculado a uma assinatura ativa. Não receber indica que o endereço não corresponde a uma conta com acesso.

## O console

No computador, o menu lateral lista os módulos, todos disponíveis em qualquer plano ativo. Para o uso no celular, consulte a seção "No celular".

`Dashboard`
: Visão geral da conta. Plano atual, consumo de quota no período e atalhos para os módulos. Sempre disponível.

`Recursos`
: Hub de ferramentas, feeds, recursos OSINT, referências e mapas de ameaças, organizados por categoria e com busca. Material de apoio para o dia a dia. Sempre disponível.

`Ask`
: Chat de cibersegurança assistido por IA, com histórico de conversas persistido. Usa os modelos Sheep conforme o seu plano. Detalhes dos modelos em `sheep-api/models.md`. Cada resposta tem um botão de leitura em voz alta pela voz do próprio aparelho, sem custo. Quem quiser uma voz gerada por IA, com qualidade de estúdio, liga o **Áudio aprimorado (Voz Sheep)** em Conta > Preferências e escolhe uma das três vozes (Sophie, Atlas ou Orion, com amostra para ouvir antes): o custo é explicado nesse momento (preço por caractere lido, exibido na própria tela) e, a partir daí, cada resposta ganha o botão "Gerar áudio", que gera o áudio na hora e mostra quantos tokens foram descontados. O áudio gerado fica disponível por 7 dias para ouvir de novo sem novo custo. Respostas muito longas são lidas até 4.000 caracteres; trechos de código não são lidos. O recurso não está disponível no período de teste. Há também o **modo conversa**: o botão de microfone ao lado do campo de mensagem ouve a sua pergunta (reconhecimento de voz do próprio navegador, sem custo), envia como texto e a Sheep responde falando frase a frase enquanto a resposta ainda está sendo escrita; quando termina, volta a ouvir. Com o Áudio aprimorado ligado a resposta falada usa a Voz Sheep (descontada dos tokens); desligado, usa a voz do aparelho. Para encerrar, toque em Encerrar ou no microfone. No campo de mensagem, as setas para cima e para baixo percorrem as perguntas já enviadas na conversa aberta.
**Sheep Agent, o modo agente do Ask** (Sheep Pro e Sheep Pro Max): o botão **Agente**, ao lado do microfone e do anexo, liga o Sheep Agent na conversa. Ele começa desligado. Ligado, a Sheep trata a mensagem como uma tarefa: consulta por conta própria CVEs, o MITRE ATT&CK, o Ransomware Intel, os feeds e a base de indicadores conhecidos, mostra cada consulta enquanto trabalha e no fim responde com os dados obtidos. O modo usa o Sage 120B. As consultas não consomem tokens. Cada passo do Sage consome tokens do plano como uma resposta comum, e a análise completa de um indicador também (até 3 por tarefa). Cada tarefa tem limite de 30 passos e 200 mil tokens, e o botão **Parar** encerra a tarefa mantendo o que já foi feito. Peça um arquivo e ele entrega o resultado em PDF, HTML, Markdown, CSV, JSON ou texto, com o botão Baixar logo abaixo da resposta (até 3 arquivos por tarefa). O arquivo é montado no seu navegador e fica junto da conversa. O botão vale para a conversa: ao abrir a conversa de novo, o agente continua ligado ou desligado como estava. Nos outros planos o botão aparece trancado, com o plano que libera.
Em Conta > Plano e uso, quem está no Sheep Pro ou no Sheep Pro Max pode converter um gift card Black Sheep em tokens bônus do período atual (500 mil, 1 milhão ou 2 milhões, conforme o cartão), gastos primeiro e vencendo com o período; o código deixa de dar acesso Black Sheep. Arquivos suspeitos (executáveis, instaladores, ZIP, documentos com macro, atalhos) podem ser anexados ao Ask sem sair do seu computador: o navegador calcula o hash, confere o tipo real pelos bytes e procura sinais estruturais (macro, JavaScript em PDF, modelo remoto, executável dentro do ZIP, extensão dupla, empacotamento) e manda só esse resumo; a Sheep consulta o hash e os indicadores nas bases de ameaças e responde. Um hash sem registro não significa arquivo limpo, e a resposta deixa isso claro. O Ask também lê imagens: anexe, arraste ou cole uma captura de tela (e-mail de phishing, alerta, log, nota de resgate, diagrama) junto com a pergunta. A imagem é reduzida no seu navegador, a Sheep extrai o texto e a descrição e responde com todo o contexto de inteligência (indicadores enriquecidos, MITRE ATT&CK, notícias). A imagem não fica guardada; só o texto extraído entra na conversa. A leitura é cobrada em tokens junto com a resposta, proporcional ao tamanho da imagem.

No Analyze, uma lista de indicadores pode ser importada de uma vez: um bundle STIX 2.1, uma exportação do MISP (JSON ou CSV), um CSV ou uma lista em texto. O arquivo é lido no navegador, os indicadores reconhecidos (IP, domínio, URL, hash, CVE) aparecem para revisão e os selecionados são analisados um a um, cada um debitando tokens como uma análise normal. O resultado pode ser exportado em CSV.

`Analyze`
: Análise de indicadores de comprometimento. Informe um IP, domínio, hash, CVE ou URL e receba o enriquecimento consolidado. Recebe também indicadores encaminhados por outros módulos e exporta o resultado em PDF.

`DFIR`
: Relatório de resposta a incidente. Você descreve o caso e informa os indicadores; o módulo analisa cada indicador, mapeia MITRE ATT&CK e redige as seções (avaliação técnica, contenção, erradicação e recuperação, detecção e recomendações), pronto para exportar em PDF.

`Pulse`
: Briefings de CTI sob demanda. Configure o perfil de interesse, gere o briefing e consulte o histórico. Exporta em PDF. Detalhamento completo do produto em `sheep-pulse/README.md`.

`Ransomware Intel`
: Vítimas recentes e grupos de ransomware monitorados, com filtros por grupo, setor e severidade.

`Feeds`
: Stream de inteligência de ameaças consolidado pela Sheep. Leitura contínua de itens recentes de CTI. Cada indicador encontrado pode ser enviado direto para o módulo Analyze. O botão **Gerar resumo do dia** faz a Sheep AI ler as últimas 24 horas de todos os feeds e organizar os destaques em sete partes: resumo executivo, destaques do dia, vulnerabilidades (as exploradas ativamente primeiro), ransomware, ameaças e vazamentos, indicadores e o que fazer hoje. O resumo consome tokens do plano, como uma pergunta no Ask, e sai no idioma do console. Pedir de novo no mesmo idioma em até 30 minutos reabre o mesmo resumo, sem nova cobrança. Cada resumo fica 7 dias em **Resumos salvos**, com download em PDF e Markdown, e depois é apagado. As vítimas de ransomware citadas são alegações publicadas pelos próprios grupos, não incidentes confirmados.

`Conta`
: Gestão da assinatura, das credenciais e da verificação em duas etapas. Sempre disponível.

Para comparar o que cada plano inclui, consulte a seção a seguir, `sheep-api/plans-and-quota.md` ou a Sheep Store em `https://sheep.byfranke.com/pages/store`.

## O que muda entre os planos

Todos os módulos abrem em qualquer plano ativo, inclusive no teste. O que muda de um plano para outro são os limites e alguns recursos. O que o seu plano não inclui continua à vista, trancado, com o plano que libera e o link da Sheep Store:

* Ask: escolher o modelo. No teste a Sheep escolhe sozinha. Scout 8B e Hunter 17B a partir do Sheep Plus e do Black Sheep, Sage 120B a partir do Sheep Pro.
* Ask: Sheep Agent (modo agente), a partir do Sheep Pro.
* Voz Sheep (Conta > Preferências): nos planos pagos.
* Pulse: 1 briefing no total no teste, 1 por dia no Sheep Plus e no Black Sheep, 30 por dia no Sheep Pro e 50 por dia no Sheep Pro Max. O envio automático (todos os dias, a cada 3 dias ou semanal) fica nos planos pagos e conta nesse limite.
* Radar do Pulse: 1 domínio no Sheep Plus e no Black Sheep, 5 no Sheep Pro e 20 no Sheep Pro Max. Nenhum no teste.
* Conta > Plano e uso: add-ons de tokens e conversão de gift card em tokens bônus, no Sheep Pro e no Sheep Pro Max.
* Conta > Convites: link de convite com tokens bônus, nos planos pagos.

A tabela completa está em `sheep-api/plans-and-quota.md`, seção "Comparação dos planos".

## Notificações

O sino no canto superior direito do console avisa o que ficou pronto e o que mudou na sua conta:

- Pulse, relatório DFIR ou resumo do dia pronto, e relatório DFIR salvo pelo Sheep MCP. Se você está na tela do relatório quando ele termina, o aviso fica só no sino, sem a mensagem flutuante.
- Novo Pulse automático, ou Pulse automático pausado por falta de tokens.
- Radar: primeira análise de um domínio, domínio autorizado por e-mail, nota pior ou ponto crítico ou alto novo.
- Tokens bônus de convite creditados.
- 80%, 95% e 100% dos tokens do período usados, parcela da semana alcançada, e o fim do teste ou de um plano que não renova sozinho.
- Avisos da equipe Sheep: novidades, recursos novos e atualizações da plataforma.

Um ponto vermelho no sino indica que há avisos não lidos. Clicar num aviso leva à tela dele. As notificações ficam 60 dias.

## Tour de primeiro acesso

No primeiro acesso, o console abre um tour curto pelo Dashboard: onde ficam os módulos, a pergunta rápida à Sheep AI, o Analyze e o DFIR, o Feeds, o Pulse e o Ransomware Intel, a busca rápida, o sino, o menu da conta e as Integrações. Dá para pular a qualquer momento (**Pular tour** ou Esc) e avançar ou voltar com as setas do teclado. Concluído ou pulado, ele não aparece de novo naquela conta, em nenhum aparelho. Para rever, abra **Conta > Preferências > Ver o tour de novo**.

## Busca rápida e menu da conta

**Ctrl K** (ou **⌘ K** no Mac), ou a lupa ao lado do sino, abre a busca rápida em qualquer tela do console. Digite parte do nome e use as setas e o Enter:

- **Ir para**: qualquer módulo, e também Radar, Plano e uso, Token da API e Preferências.
- **Relatórios e conversas**: relatórios DFIR, briefings do Pulse, resumos do dia e conversas do Ask salvos na conta, que abrem direto.
- **Ações**: nova conversa no Ask, analisar um indicador, novo relatório DFIR, gerar Pulse, gerar resumo do dia e monitorar um domínio. Se o texto digitado for um IP, domínio, URL, hash ou CVE, a primeira ação é **Analisar** aquele indicador. A última linha é sempre **Perguntar à Sheep**, que envia o texto como pergunta ao Ask. As duas rodam na hora e consomem tokens do plano.

Sem nada digitado, a busca mostra os itens salvos mais recentes.

O botão do plano, no canto superior direito, abre o menu da conta: o plano, quanto dos tokens do período já foi usado, até quando vai o período, e atalhos para Conta, Preferências, Integrações e Sair.

Relatórios DFIR e resumos do dia salvos abrem numa janela de leitura por cima da tela, com PDF e Markdown. Os que você acabou de gerar continuam aparecendo na própria página.

## Quanto tempo o seu conteúdo fica guardado

Conversas do Ask, briefings do Pulse e relatórios DFIR seguem a mesma regra. Cada item fica **ativo por 30 dias** desde o último uso. Depois vai para a **Lixeira** do módulo, onde fica mais 30 dias: dá para restaurar (o prazo recomeça) ou excluir na hora. Apagar qualquer item também o manda para a Lixeira. O console mostra em cada item quando ele sai. Passados os 60 dias, o item some do console e fica guardado cifrado por 6 meses, só para atender a ordem judicial ou obrigação legal, com uma chave que a própria plataforma não consegue abrir; depois disso é destruído. No Ask há "Apagar todas" e "Esvaziar lixeira". Para quem já usava a Sheep antes de 09/11/2026, nada vai para a Lixeira automaticamente antes de 09/12/2026.

Os resumos do dia da aba Feeds têm prazo próprio: ficam 7 dias em Resumos salvos e depois são apagados, sem passar pela Lixeira nem pelo arquivo.

## No celular

No celular e em telas estreitas, o console se ajusta para uso com uma mão. O menu lateral dá lugar a uma barra de navegação fixa na base da tela, e o conteúdo ocupa a largura inteira.

A barra inferior reúne os módulos de uso mais frequente para acesso direto. O botão `Menu` abre a lista completa dos demais módulos e a opção de sair da conta.

No módulo Ask, a lista de conversas abre pelo botão de conversas no topo e fecha sozinha ao escolher uma conversa.

Todos os módulos continuam disponíveis no celular.

## Gerenciar a conta

No módulo Conta você pode:

* Consultar o plano atual, o período de cobrança e o saldo de quota.
* Gerar o token da API. O token é entregue por e-mail, nunca exibido em tela.
* Revogar o token atual quando precisar substituir a credencial.
* Listar as sessões ativas do console e encerrar qualquer uma delas.
* Vincular a sua conta Discord à assinatura, quando aplicável.
* Copiar o seu link de convite e acompanhar os tokens bônus recebidos. Detalhes em `sheep-platform/convites.md`.
* Ativar ou desativar a verificação em duas etapas (2FA).
* Enviar um relatório de bug ou sugestão pela seção de suporte.

O token segue o mesmo modelo das demais superfícies. A entrega exclusivamente por e-mail protege contra exposição acidental em capturas de tela e gravações. Para o fluxo completo de emissão e uso do token, consulte `getting-started.md` e `sheep-api/authentication.md`.

## Sessões e segurança

A sessão do console expira depois de 3 dias sem uso. Cada uso renova esse prazo, até o limite de 7 dias desde o login. Ao passar de qualquer um dos dois limites, você volta para a tela de acesso e precisa solicitar um novo link, mesmo que use o console todos os dias.

Você pode abrir o console em mais de um dispositivo. Cada acesso cria uma sessão própria. Para encerrar o acesso em um dispositivo, use a lista de sessões no módulo Conta ou clique em "Sair" no próprio dispositivo.

Encerre a sessão sempre que usar um computador compartilhado.

## Verificação em duas etapas (2FA)

A verificação em duas etapas é opcional e adiciona uma segunda etapa ao login, com um aplicativo autenticador (Google Authenticator, Authy, 1Password ou similar). Quem não ativa segue com o login normal.

Para ativar, no módulo Conta:

1. Clique em "Ativar 2FA".
2. Escaneie o QR code no seu app autenticador, ou informe o código manual exibido.
3. Digite o código de 6 dígitos gerado pelo app para confirmar.
4. Guarde os códigos de backup mostrados na tela. Cada um funciona uma única vez e serve para entrar caso você perca o acesso ao app. Eles não são exibidos novamente.

Com a 2FA ativa, todo login pede o código de 6 dígitos depois do link do e-mail. Um código de backup também é aceito nesse campo.

Para desativar, no módulo Conta, clique em "Desativar 2FA" e confirme com um código atual do app ou de backup.

## Solução de problemas

`Não recebi o e-mail de acesso`
: Verifique a caixa de spam. Confirme que informou o e-mail vinculado à assinatura. Para planos pagos, é o e-mail usado no checkout da Sheep Store. Se o endereço não estiver vinculado a uma assinatura ativa, nenhum e-mail é enviado. Aguarde alguns minutos antes de pedir um novo link, pois solicitações seguidas são limitadas.

`O link de acesso não funciona`
: O link é de uso único e expira após alguns minutos. Se já passou do prazo ou você já usou, volte para `https://sheep.byfranke.com/login` e solicite um novo.

`Um recurso aparece trancado`
: O recurso é de um plano acima do seu ou não faz parte do período de teste. O cartão trancado mostra qual plano libera e leva à Sheep Store. Compare os planos em `sheep-api/plans-and-quota.md`.

`Voltei para a tela de acesso sozinho`
: A sessão expirou após o período de validade. Solicite um novo link de acesso e entre novamente.

`Não passo da etapa do código (2FA)`
: Confira se o horário do dispositivo do autenticador está correto, pois o código depende da hora. Se não tiver acesso ao app, use um dos seus códigos de backup no mesmo campo. Após várias tentativas, a verificação é bloqueada por segurança; nesse caso, solicite um novo link de acesso e tente de novo.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
