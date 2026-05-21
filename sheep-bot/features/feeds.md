# Sheep Feeds

Sheep Feeds é o recurso do Sheep Bot que publica feeds de Threat Intelligence diretamente em canais do seu servidor Discord. Cada feed roda em um canal dedicado, com posts automáticos quando há novo conteúdo.

Os feeds estão divididos em dois grupos:

* Feeds gratuitos, gerenciados pelo comando `/feeds`. Disponíveis em qualquer servidor.
* Feeds pagos, gerenciados pelo comando `/blackfeeds`. Exigem membership Black Sheep ativa do administrador que ativa o canal.

## Quem pode configurar

Administradores do servidor com permissão Manage Server (Gerenciar Servidor) no Discord.

Para `/blackfeeds`, o administrador também precisa ter membership Black Sheep ativa vinculada à conta. Para outros planos pagos (Pro, Pro Max, Enterprise), os feeds pagos seguem habilitados quando a conta tem benefícios de Black Sheep ativos ou um período de Black Sheep em paralelo.

## Feeds gratuitos

Três feeds gratuitos cobrem o uso essencial de uma comunidade de cibersegurança.

### Cybersecurity News

Identificador: `RSS_NEWS_MONITOR`

Notícias agregadas de cibersegurança publicadas por sites de imprensa especializada. Atualização a cada poucos minutos. Cada post traz título, sumário curto e link direto para a matéria original.

Slug do canal: `sheep-news`.

### IOC Stream

Identificador: `IOC_STREAM_MONITOR`

Stream em tempo quase real de Indicadores de Comprometimento (IPs, domínios, hashes, URLs maliciosas) extraídos de fontes públicas de threat intelligence. Cada post traz o valor do IOC, a fonte e o timestamp de primeira observação.

Use para alimentar blocklists internas, regras de hunting ou awareness contínuo.

Slug do canal: `sheep-iocs`.

### CVE Alerts

Identificador: `CVE_MONITOR`

Alertas em tempo quase real de CVEs publicados com severidade alta ou crítica. Cada post inclui o ID do CVE, o score CVSS, vendor ou produto afetado quando informado, e sumário de uma linha. Vulnerabilidades de severidade baixa e média são filtradas para reduzir ruído.

Slug do canal: `sheep-vulnerabilities`.

## Feeds pagos

Os feeds pagos exigem membership Black Sheep ativa. Cobrem áreas especializadas que complementam os feeds gratuitos.

* **Ransomware Monitor** (`RANSOMWARE_MONITOR`). Atividade de operações de ransomware, novas vítimas e posts em sites públicos de vazamento.
* **Threat Intel Monitor** (`THREAT_INTEL_MONITOR`). Relatórios e análises de threat intelligence publicados por vendors e pesquisadores independentes.
* **APT Infrastructure Monitor** (`APT_INFRASTRUCTURE_MONITOR`). Indicadores de infraestrutura associada a operações de APT, incluindo servidores C2 e domínios de phishing.
* **Data Leak Monitor** (`DATA_LEAK_MONITOR`). Eventos públicos de vazamento e exposição de dados corporativos.
* **ICS/SCADA Monitor** (`ICS_SCADA_MONITOR`). Vulnerabilidades e alertas em sistemas de controle industrial.
* **Vendor Research Monitor** (`KASPERSKY_MONITOR`). Pesquisa e relatórios técnicos publicados por laboratórios de pesquisa de segurança.
* **Financial Intel Monitor** (`FINANCIAL_INTEL_MONITOR`). CTI na fronteira entre cibercrime e o sistema financeiro: designações OFAC SDN, ações de enforcement, takedowns de mixers, análises on-chain. Cada entrada inclui categoria (`[SANCTION]`, `[RANSOM-PAY]`, `[MIXER]`, `[EXCHANGE]`, `[ENFORCEMENT]`, `[ADVISORY]`, `[ANALYSIS]`) e quando aplicável extrai IOCs de carteira (BTC, ETH, TRX) presentes no relatório.

## Como configurar

A configuração é a mesma para `/feeds` e `/blackfeeds`. As ações disponíveis em ambos os comandos:

### enable

Cria um canal dedicado no servidor para o feed escolhido e ativa a publicação automática.

```
/feeds action:enable feed:cybersecurity_news
/blackfeeds action:enable feed:ransomware_monitor
```

O bot cria um canal com slug `sheep-<nome>` e publica as configurações no canal de log do servidor.

### status

Mostra a lista de feeds ativos no servidor, com canal de destino e última atualização.

```
/feeds action:status
/blackfeeds action:status
```

### list

Lista todos os feeds disponíveis no comando, com nome, descrição e estado atual no servidor.

```
/feeds action:list
/blackfeeds action:list
```

### disable

Suspende a publicação automática em um canal sem apagar o canal. Útil para pausar temporariamente.

```
/feeds action:disable feed:ioc_stream
```

Quando você reativar o feed com `enable`, a publicação retoma no mesmo canal.

### delete

Remove o canal dedicado ao feed do servidor.

```
/feeds action:delete feed:ioc_stream
```

Diferente do `disable`, o `delete` apaga o canal. Use quando o feed não for mais usado.

## Boas práticas

Crie uma categoria dedicada para os feeds. O bot cria os canais na categoria padrão configurada para o Sheep; se você quiser organização visual, mova os canais para uma categoria "Sheep Feeds" depois da primeira ativação.

Ative apenas os feeds que sua comunidade vai consumir. Cada feed gera tráfego contínuo. Canais inativos viram ruído.

Para servidores com plano Black Sheep, considere começar pelos feeds gratuitos e migrar para os pagos conforme a equipe pede maior profundidade. Os feeds pagos são complementares, não substituem os gratuitos.

Quando a membership Black Sheep do administrador expira, os feeds pagos pausam automaticamente. O bot publica aviso no canal e retoma a publicação assim que a membership for renovada. Não há perda de canal nem reconfiguração necessária.

## Limites de publicação

Os feeds aplicam um teto de até dez posts por ciclo de checagem em cada canal. Esse teto evita inundar o canal quando há grande volume de itens novos. Itens que ultrapassam o teto entram na próxima execução do ciclo.

A frequência dos ciclos varia por feed, tipicamente entre cinco e quinze minutos.
