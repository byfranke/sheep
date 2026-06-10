# Sheep Platform

Sheep Platform é o console web da Sheep. Um único acesso reúne os produtos da plataforma em uma só tela: feeds de inteligência, chat de cibersegurança, análise de indicadores, briefings sob demanda e a gestão da sua conta. Em vez de abrir portais separados, você navega entre os módulos por um menu lateral, com um login só.

Use o console quando preferir operar pelo navegador, sem terminal nem integração própria. O histórico é compartilhado com os demais produtos. As conversas e os briefings gerados aqui aparecem também nas superfícies equivalentes da plataforma, e vice-versa.

Endereço do console: `https://sheep.byfranke.com/app`.

## Pré-requisitos

* Conta Sheep com assinatura ativa: Sheep Plus, Sheep Pro, Sheep Pro Max, Black Sheep ou Black Sheep Trial.
* E-mail vinculado à sua conta. O mesmo e-mail usado para receber o token da API.

O plano gratuito comum não dá acesso ao console. Os módulos disponíveis dependem do seu plano.

## Como acessar

1. Acesse `https://sheep.byfranke.com/login`.
2. Informe o e-mail vinculado à sua conta e clique em "Acessar".
3. Você recebe um link de acesso por e-mail. Abra o e-mail e clique no link.
4. O console abre em `https://sheep.byfranke.com/app`.

Não há senha. Toda autenticação acontece pelo e-mail vinculado. O link de acesso é de uso único e expira após alguns minutos. A sessão dura 24 horas e se renova enquanto você usa o console.

Se você ativou a verificação em duas etapas (2FA), após clicar no link a plataforma pede um código de 6 dígitos do seu app autenticador para concluir o login.

Por segurança, a tela de acesso responde da mesma forma para qualquer e-mail informado. Receber o e-mail confirma que o endereço está vinculado a uma assinatura ativa. Não receber indica que o endereço não corresponde a uma conta com acesso.

## O console

O menu lateral lista os módulos. Os módulos incluídos no seu plano abrem direto. Os demais exibem a opção de upgrade.

`Dashboard`
: Visão geral da conta. Plano atual, consumo de quota no período e atalhos para os módulos. Sempre disponível.

`Recursos`
: Hub de ferramentas, feeds, recursos OSINT, referências e mapas de ameaças, organizados por categoria e com busca. Material de apoio para o dia a dia. Sempre disponível.

`Ask`
: Chat de cibersegurança assistido por IA, com histórico de conversas persistido. Usa os modelos Sheep conforme o seu plano. Detalhes dos modelos em `sheep-api/models.md`.

`Analyze`
: Análise de indicadores de comprometimento. Informe um IP, domínio, hash, CVE ou URL e receba o enriquecimento consolidado. Recebe também indicadores encaminhados por outros módulos e exporta o resultado em PDF.

`DFIR`
: Relatório de resposta a incidente. Você descreve o caso e informa os indicadores; o módulo analisa cada indicador, mapeia MITRE ATT&CK e redige as seções (avaliação técnica, contenção, erradicação e recuperação, detecção e recomendações), pronto para exportar em PDF.

`Pulse`
: Briefings de CTI sob demanda. Configure o perfil de interesse, gere o briefing e consulte o histórico. Exporta em PDF. Detalhamento completo do produto em `sheep-pulse/README.md`.

`Ransomware Intel`
: Vítimas recentes e grupos de ransomware monitorados, com filtros por grupo, setor e severidade.

`Feeds`
: Stream de inteligência de ameaças consolidado pela Sheep. Leitura contínua de itens recentes de CTI. Cada indicador encontrado pode ser enviado direto para o módulo Analyze.

`Conta`
: Gestão da assinatura, das credenciais e da verificação em duas etapas. Sempre disponível.

A disponibilidade de cada módulo segue o seu plano. Para comparar planos e o que cada um inclui, consulte `sheep-api/plans-and-quota.md` ou a Sheep Store em `https://sheep.byfranke.com/pages/store.html`.

## Gerenciar a conta

No módulo Conta você pode:

* Consultar o plano atual, o período de cobrança e o saldo de quota.
* Gerar o token da API. O token é entregue por e-mail, nunca exibido em tela.
* Revogar o token atual quando precisar substituir a credencial.
* Listar as sessões ativas do console e encerrar qualquer uma delas.
* Vincular a sua conta Discord à assinatura, quando aplicável.
* Ativar ou desativar a verificação em duas etapas (2FA).
* Enviar um relatório de bug ou sugestão pela seção de suporte.

O token segue o mesmo modelo das demais superfícies. A entrega exclusivamente por e-mail protege contra exposição acidental em capturas de tela e gravações. Para o fluxo completo de emissão e uso do token, consulte `getting-started.md` e `sheep-api/authentication.md`.

## Sessões e segurança

A sessão do console dura 24 horas e se renova a cada uso. Ao ficar inativo além desse período, você volta para a tela de acesso e precisa solicitar um novo link.

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

`Um módulo aparece bloqueado`
: O módulo não está incluído no seu plano. Compare os planos em `sheep-api/plans-and-quota.md` ou faça upgrade pela Sheep Store.

`Voltei para a tela de acesso sozinho`
: A sessão expirou após o período de validade. Solicite um novo link de acesso e entre novamente.

`Não passo da etapa do código (2FA)`
: Confira se o horário do dispositivo do autenticador está correto, pois o código depende da hora. Se não tiver acesso ao app, use um dos seus códigos de backup no mesmo campo. Após várias tentativas, a verificação é bloqueada por segurança; nesse caso, solicite um novo link de acesso e tente de novo.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
