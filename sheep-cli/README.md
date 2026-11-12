# Sheep CLIs

A linha Sheep CLI oferece ferramentas de linha de comando oficiais para uso em terminais, scripts shell e pipelines locais. Cada CLI tem foco específico e pode ser instalada de forma independente.

As CLIs consomem a Sheep API com o mesmo token usado em integrações via curl ou HTTP. Para emitir um token, consulte `../getting-started.md`.

## Ferramentas disponíveis

### sheep-cli

Agente para o terminal. Desde a versão 1.3.0 ele executa tarefas no seu computador (organizar arquivos, corrigir um script, investigar um log, montar um projeto) e não só responde: planeja, lê e altera arquivos, roda comandos e diz o que fez, com a inteligência de ameaças da Sheep por trás. Também traz os comandos de CTI (análise de indicadores, feeds, PIR e relatórios).

Distribuído como binário para Linux, macOS e Windows. Versões publicadas em `https://github.com/byfranke/sheep-cli/releases`. Página do produto: `https://sheep.byfranke.com/pages/sheep-cli`.

### sheep-ask-cli

Ferramenta de linha única para fazer uma pergunta e receber a resposta. Use em scripts shell, atalhos e automações locais.

Repositório público: `https://github.com/byfranke/sheep-ask-cli`.

### sheep-analyze-cli

Ferramenta especializada em análise de IOC. Lê um valor (IP, domínio, hash, URL, CVE) e retorna a análise estruturada do endpoint `/api/ai/analyze`.

Repositório público: `https://github.com/byfranke/sheep-analyze-cli`.

### sheep-feeds-cli

Ferramenta de leitura dos feeds de Threat Intelligence. Suporta filtros, paginação e formatos de saída adequados a pipelines (JSON, texto plano, tabela).

Repositório público: `https://github.com/byfranke/sheep-feeds-cli`.

## Instalação

### sheep-cli

Um comando instala o binário da sua plataforma, confere o SHA-256 contra o `SHA256SUMS` publicado na versão e coloca o `sheep-cli` no PATH.

Linux e macOS:

```bash
curl -fsSL https://sheep.byfranke.com/install.sh | bash
```

Windows (PowerShell):

```powershell
iwr https://sheep.byfranke.com/install.ps1 -UseBasicParsing | iex
```

Opções do instalador, por variável de ambiente: `SHEEP_CLI_VERSION=v1.2.5` instala uma versão específica, `SHEEP_CLI_INSTALL_DIR` muda a pasta de instalação e `SHEEP_CLI_FORCE=1` reinstala mesmo quando a versão já está instalada.

### Demais CLIs

As CLIs em Python (`sheep-ask-cli`, `sheep-analyze-cli`, `sheep-feeds-cli`) trazem as instruções no README do repositório correspondente.

## O agente do sheep-cli

A partir da versão 1.3.0, todo pedido feito no `sheep-cli` vai para o agente. Ele decide sozinho se precisa de ferramentas: listar e ler arquivos, procurar no projeto, editar, rodar comandos, manter uma lista de tarefas e consultar a Sheep sobre um IP, domínio, URL, hash ou CVE.

- **Onde ele age**: os arquivos que ele lê, cria e edita ficam dentro da pasta em que você abriu o `sheep-cli`. Dentro dela, ele cria e edita arquivos comuns sem pedir confirmação (o `/undo` desfaz). Arquivos e pastas ocultos (`.env`, `.ssh`, `.github`...) sempre pedem confirmação, assim como qualquer alteração quando você abriu o `sheep-cli` na sua pasta de usuário. Arquivos dentro de `.git` e as configurações do próprio Sheep CLI nunca são alterados.
- **Comandos**: todo comando que o agente quer rodar pede confirmação antes, a não ser que só leia dentro da pasta (`ls`, `cat`, `git status`...) ou bata com uma regra que você salvou (responda `a` para "sempre", ou use `/perms`). Uma regra nunca cobre um comando encadeado (com `;`, `&&`, `|`, redirecionamento ou várias linhas). Para só ver o plano sem executar nada, use o modo `plan`.
- **Segredos**: senhas, chaves e tokens que aparecem em arquivos e saídas de comando são mascarados antes de qualquer envio à Sheep.
- **Desfazer**: `/undo` mostra e devolve os arquivos que o agente mudou na última tarefa, e apaga os que ele criou. Comandos executados não são desfeitos.
- **Instruções do projeto**: um arquivo `SHEEP.md` (ou `AGENTS.md`) na pasta diz ao agente como trabalhar ali, por exemplo como rodar os testes. `~/.sheep-cli/SHEEP.md` vale para todos os projetos.
- **Limites e custo**: o agente usa tokens do seu plano a cada passo. Por padrão ele para em 30 passos ou 200 mil tokens por tarefa e avisa ao chegar em 80%. `/agent` mostra e muda esses limites (`/agent steps 50`, `/agent budget 300k`), e `/agent off` volta ao comportamento anterior, em que as ferramentas só entram quando o pedido fala de arquivos ou comandos.
- **Ligado por padrão com o Sage** (1.4.3): com `/model auto` num plano que inclui o Sage (Sheep Pro e Sheep Pro Max) ou com `/model sage`, todo pedido vai para o agente. Com o Hunter ou o Scout, os pedidos vão para o chat e o agente entra quando você pede uma ação (criar, editar, rodar, procurar nos arquivos), porque tarefas longas de vários passos funcionam melhor no Sage. `/agent on` mantém o agente ligado com qualquer modelo e `/agent auto` volta a este padrão.
- **Modelo**: nos planos Sheep Pro e Sheep Pro Max o agente usa o Sage 120B por padrão. Um modelo escolhido com `/model` sempre prevalece.
- **Simulação**: no modo `plan` (TAB numa linha vazia) o agente lê o projeto e descreve o plano, sem alterar nada.
- **Inteligência da Sheep como ferramenta** (1.4.0): o agente consulta CVEs, técnicas, grupos e softwares do MITRE ATT&CK, o Ransomware Intel (perfil de um grupo ou vítimas recentes) e os feeds de ameaças, sem custo de tokens. Também escreve um relatório de incidente (DFIR), salvo na Sheep Platform, que usa tokens.
- **Modos de permissão** (1.4.0): `/agent mode edits` é o padrão descrito acima. `/agent mode ask` mostra também cada alteração de arquivo comum (linhas removidas e adicionadas) e pergunta antes de aplicar.
- **Páginas web** (1.4.0): o agente lê uma página quando a tarefa pede. Ele pergunta antes de cada site novo, nunca acessa endereços da sua rede local nem de metadados de nuvem, e trata o texto como informação, nunca como instrução. Depois de ler uma página ou um feed, todo comando passa a pedir confirmação até o fim da tarefa.
- **Scripts e CI** (1.4.0): `sheep-cli -p "<tarefa>"` roda uma tarefa sem a tela interativa (`-p -` lê a tarefa da entrada padrão). A resposta sai na saída padrão e os passos na saída de erro, e `--json` devolve um resultado estruturado. Nada pode ser confirmado nesse modo: o que precisaria de confirmação é recusado e listado no fim com a opção `--allow` que libera. Código de saída 0 quando a tarefa terminou, 2 quando parou num limite e 1 em erro.
- **Windows** (1.4.0): os comandos rodam no PowerShell (o PowerShell 7 quando instalado). `SHEEP_CLI_SHELL=cmd` volta ao Prompt de Comando.

## Atualização do sheep-cli

Rode de novo o comando de instalação. O instalador compara a versão instalada com a mais recente: se forem iguais, ele avisa e não baixa nada. Se houver versão nova, ele troca o binário e mantém o token, as sessões e as preferências, que ficam em `~/.sheep-cli/`.

A partir da versão 1.2.5, o `sheep-cli` avisa ao abrir quando existe versão nova, no máximo uma vez por dia, e nunca baixa nada sozinho. Dentro do REPL, o `/update` consulta na hora e mostra o comando para o seu sistema. Para desligar o aviso diário, defina `SHEEP_CLI_NO_UPDATE_CHECK=1`.

## Configuração de token

Gere ou troque o token na Sheep Platform, em Conta: `https://sheep.byfranke.com/app#account`.

No `sheep-cli`, o caminho mais simples é rodar `sheep-cli` e colar o token quando ele pedir. O token fica em `~/.sheep-cli/config.json`, legível só pelo seu usuário. A partir da versão 1.2.5, o `sheep-cli` também lê a variável de ambiente `SHEEP_API_TOKEN`, que tem prioridade sobre o arquivo e nunca é gravada em disco. É a forma indicada para scripts, CI e gerenciadores de segredos.

As CLIs em Python aceitam o token por uma das formas abaixo, em ordem de precedência:

1. Argumento de linha de comando dedicado (`--token`, `-t` ou similar).
2. Variável de ambiente `SHEEP_API_TOKEN`.
3. Arquivo de configuração próprio da CLI (cada projeto define a localização).

Em scripts, configure a variável no início do script ou injete via gerenciador de segredos.

```bash
export SHEEP_API_TOKEN="shp_API_KEY_AQUI"
```

Não passe o token literalmente em comandos. Histórico de shell, prints e logs de processo podem capturar o valor.

## Suporte

Issues técnicas: abra no repositório GitHub correspondente.

Dúvidas gerais: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
