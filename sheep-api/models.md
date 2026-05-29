# Modelos

A Sheep API expõe quatro identificadores de modelo. O parâmetro `model` em `/api/ai/ask` e `/api/ai/analyze` aceita esses valores.

Os três tiers nomeados da Sheep AI são **Scout 8B**, **Hunter 17B** e **Sage 120B**. O sufixo `XB` indica a capacidade relativa entre eles, da menor para a maior. O quarto identificador é `auto`, que escolhe automaticamente entre Scout 8B e Hunter 17B conforme a complexidade da pergunta.

A escolha do modelo define duas coisas:

* O perfil da resposta. Cada modelo tem profundidade analítica própria.
* O consumo da sua quota. Modelos mais robustos consomem mais tokens Sheep por chamada. Sage 120B consome mais que Hunter 17B, que consome mais que Scout 8B.

## auto

Identificador: `auto`

Padrão. Quando o parâmetro `model` é omitido, esse valor é assumido.

O `auto` direciona cada pergunta para um dos tiers Scout 8B ou Hunter 17B conforme a complexidade detectada. Perguntas casuais e definições rápidas seguem para Scout 8B. Perguntas analíticas com IOCs, logs ou frameworks vão para Hunter 17B.

O modelo Sage 120B nunca é selecionado automaticamente. Use `auto` quando quiser equilíbrio entre custo e qualidade sem precisar decidir manualmente.

O campo `served_by` na resposta informa qual tier atendeu de fato. O consumo da sua quota segue esse tier.

Disponível em todos os planos pagos.

## scout

Identificador: `scout`. Nome de exibição: **Scout 8B**.

Rápido e leve. Use para definições, checagens factuais curtas, perguntas conceituais e conversação leve.

Saída típica: dois a quatro parágrafos curtos ou uma lista numerada de até seis itens.

Disponível em todos os planos pagos.

## hunter

Identificador: `hunter`. Nome de exibição: **Hunter 17B**.

Default analítico. Use para análise de logs, triagem de vulnerabilidades, perfil de APT, mapeamento para MITRE ATT&CK, análise multi-fonte de IOCs e respostas com narrativa estruturada.

Saída típica: resposta segmentada em blocos, com lista de TTPs, IOCs deduplicados e referências quando o contexto pede.

Disponível em todos os planos pagos.

## sage

Identificador: `sage`. Nome de exibição: **Sage 120B**.

Análise profunda. Use para atribuição formal de incidente, briefings executivos, correlação entre múltiplos incidentes e relatórios baseados em frameworks (Diamond Model, Kill Chain, Pyramid of Pain, F3EAD).

Saída típica: relatório estruturado com sumário executivo, evidências, hipóteses concorrentes quando aplicável e recomendações. O Sage 120B declara explicitamente quando o contexto disponível é insuficiente, em vez de inferir.

Disponível apenas em Sheep Pro e Sheep Pro Max. Tentativas em planos sem direito retornam `403 Forbidden` com código `model_not_allowed`.

## Como escolher o tier

A escolha ideal depende do tipo de pergunta. Esta seção orienta a decisão.

### Use Scout quando

* A pergunta é uma definição curta. Exemplo: "diferencie IDS de IPS", "o que é DKIM".
* A resposta esperada cabe em dois ou três parágrafos.
* A pergunta não exige citação de IDs MITRE ATT&CK específicos. Para pedidos com IDs, prefira Hunter.
* O contexto é conversacional (saudação, pedido de ajuda genérico, esclarecimento).

Não use Scout para atribuição de APT, mapeamento de TTPs em campanhas reais, correlação multi-incidente ou pedido de relatório estruturado. O tier não foi calibrado para essas tarefas.

### Use Hunter quando

* A pergunta envolve análise de IOC, perfil de grupo de ameaça, mapeamento de etapas de uma campanha contra técnicas MITRE.
* A resposta deve trazer estrutura (lista de TTPs, IOCs, recomendações), mas sem o tom formal de relatório executivo.
* O caso pede correlação entre frameworks (Kill Chain, Diamond Model, ATT&CK) sem necessariamente atribuir formalmente a um ator.
* Você precisa de boa relação entre profundidade analítica e custo em tokens. Para a maior parte do trabalho cotidiano de CTI, Hunter é a escolha equilibrada.

### Use Sage quando

* A saída precisa do formato de relatório executivo (Resumo, Análise Detalhada, Caveats, Recomendações) para anexar a um ticket de incidente ou comunicar a um stakeholder não-técnico.
* A análise depende de citação explícita de fontes públicas (papers acadêmicos com autoria, advisories CISA/FBI, MITRE Groups pages).
* O caso exige distinguir hipóteses concorrentes com nível de confiança declarado.
* A pergunta cobre atribuição de incidentes históricos (Stuxnet, SolarWinds, Colonial Pipeline) onde a profundidade de contexto compensa o custo.

Sage tende a explicitar quando o contexto disponível é insuficiente para uma conclusão definitiva. Esse comportamento conservador é útil em produção mas pode soar verboso para perguntas simples.

### Resumo rápido

* Definição factual curta sem IDs MITRE: **Scout 8B**.
* Análise CTI cotidiana, com IOCs ou TTPs: **Hunter 17B**.
* Briefing executivo ou atribuição com fontes nomeadas: **Sage 120B**.
* Em dúvida ou pergunta de natureza imprevisível: **`auto`** (a API roteia entre Scout 8B e Hunter 17B, nunca Sage 120B).

## Descobrir modelos disponíveis

Para descobrir os modelos dinamicamente, consulte `GET /api/ai/models`. Esse endpoint não exige autenticação e retorna a lista oficial com nome de exibição e descrição em português e inglês.

Para descobrir quais modelos a sua conta tem direito, consulte `GET /api/profile`. O campo `plan.allowed_models` traz a lista permitida pelo plano vigente.

## Estabilidade do roteador

A lógica interna do roteador do `auto` pode evoluir entre versões. Se a sua integração exige determinismo absoluto sobre qual modelo atende, especifique o valor de forma explícita.

## Sem fallback entre modelos

A API não troca de modelo automaticamente em caso de erro de geração. Se o modelo escolhido falhar, o erro é propagado ao cliente. A redundância operacional acontece em outra camada, descrita em `errors.md`.
