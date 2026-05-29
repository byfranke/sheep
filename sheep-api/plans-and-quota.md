# Planos e Quota

A Sheep API mede consumo em tokens Sheep, não em número de requisições. Cada plano define um teto mensal de tokens.

## Tokens Sheep

Um token Sheep corresponde a um fragmento de texto processado pelo modelo de IA, tipicamente entre três e quatro caracteres em português ou inglês. A medição cobre o prompt enviado ao modelo somado à resposta gerada.

Uma única chamada pode consumir de algumas centenas a alguns milhares de tokens, conforme o tamanho da pergunta, o modelo usado e o tamanho da resposta. Por isso, planejar consumo em termos de tokens é mais preciso do que pensar em número de requisições.

O valor cobrado em cada chamada aparece no campo `tokens_used` da resposta. Os detalhes de prompt e completion estão no bloco `usage`.

## Planos disponíveis

Cada plano expõe um teto mensal de tokens Sheep e define quais modelos estão liberados.

### Sheep Plus

Identificador: `pro`

Teto mensal: 300.000 tokens Sheep.

Modelos liberados: `auto`, `scout`, `hunter`.

### Sheep Pro

Identificador: `pro_max`

Teto mensal: 1.000.000 tokens Sheep.

Modelos liberados: `auto`, `scout`, `hunter`, `sage`.

### Sheep Pro Max

Identificador: `enterprise`

Teto mensal: 4.000.000 tokens Sheep.

Modelos liberados: `auto`, `scout`, `hunter`, `sage`.

### Black Sheep

Identificador: `black_sheep`

Resgate por gift card mensal, semestral ou anual ativado no Discord.

Teto: 167.000 tokens Sheep por mês de duração. Um gift card de 6 meses libera 1.000.000 tokens no período total.

Modelos liberados: `auto`, `scout`, `hunter`.

### Black Sheep Trial

Identificador: `black_sheep_trial`

Avaliação de 3 dias ativada pelo Discord.

Teto: 30.000 tokens Sheep no período total.

Modelos liberados: `auto`, `scout`, `hunter`.

## Add-ons

Planos Sheep Pro (identificador `pro_max`) e Sheep Pro Max (identificador `enterprise`) aceitam add-ons recorrentes que ampliam o teto mensal sem mudar de plano. Os add-ons disponíveis hoje:

* `tokens_2m` adiciona 2.000.000 tokens Sheep por mês.
* `tokens_4m` adiciona 4.000.000 tokens Sheep por mês.

Um cliente pode ter mais de um add-on ativo ao mesmo tempo. O teto efetivo do período é o teto do plano somado a todos os add-ons ativos. A composição completa aparece em `GET /api/profile`.

## Período de avaliação

Os planos pagos podem ser ofertados com um período de avaliação na Sheep Store. Durante esse período, a assinatura entra com `status: trialing` em `GET /api/profile` e o teto efetivo do período corrente é menor que o teto mensal regular do plano.

* Sheep Plus em avaliação: 30.000 tokens Sheep para a janela inteira.
* Sheep Pro em avaliação: 60.000 tokens Sheep para a janela inteira.
* Sheep Pro Max em avaliação: 100.000 tokens Sheep para a janela inteira.

O teto é aplicado ao período total da avaliação, sem proporção por dia. Add-ons ativos não somam tokens durante a avaliação. Ao final do período, se a assinatura transitar para `active`, o contador zera, o novo período inicia e o teto mensal regular do plano passa a valer.

Para acompanhar a transição, consulte `subscription.status` em `GET /api/profile`. Quando o valor sai de `trialing` e vai para `active`, o `usage.current_period_budget` ajusta automaticamente para o teto mensal regular.

## Consumo por modelo

Cada modelo consome tokens da sua quota de forma diferente conforme a profundidade da análise.

* Scout 8B é o mais econômico. Ideal para perguntas curtas e factuais.
* Hunter 17B consome mais que Scout 8B. Equilíbrio entre profundidade analítica e custo, recomendado para o trabalho cotidiano de CTI.
* Sage 120B é o que mais consome. Use quando a tarefa exige relatório executivo ou atribuição formal.
* O modo `auto` segue o consumo do modelo que efetivamente atendeu a requisição, informado no campo `served_by` da resposta.

O campo `tokens_used` na resposta já reflete o consumo real da sua quota e é o valor que reduz seu saldo em `GET /api/profile`.

## Período de billing

Cada plano define um período de billing.

* Sheep Plus, Sheep Pro e Sheep Pro Max seguem a cadência da assinatura paga (mensal ou anual).
* Black Sheep tem período igual à duração do gift card resgatado.
* Black Sheep Trial tem período de 3 dias corridos.

No fim do período, o contador de consumo zera e um novo ciclo começa automaticamente.

Quotas anuais escalonam de forma proporcional. Um Sheep Plus anual recebe um único período com teto de 300.000 × 12 = 3.600.000 tokens, em vez de 12 ciclos de 300.000.

## Estouro de quota

A API impede consumo além do teto. Antes de cada chamada à IA, o servidor estima o custo mínimo e verifica saldo. Se não cobrir, a chamada é rejeitada com `402 Payment Required` e código `quota_exceeded`. Não há débito sem geração de resposta.

Não há fatura adicional automática por estouro. Para destravar antes da virada do período, contrate um add-on ou aguarde o próximo ciclo.

## Consultar saldo

Use `GET /api/profile` para ver, em tempo real:

* O plano vigente.
* Tokens consumidos no período corrente.
* Tokens restantes no período.
* Modelos liberados pelo plano.
* Add-ons ativos.
* Data do fim do período corrente.

O endpoint não consome quota.

## Múltiplas fontes

Um cliente pode acumular um plano pago e um Black Sheep ativo em paralelo. Nesse caso a conta recebe dois tokens distintos, um por fonte, cada um com sua própria quota. As quotas não somam automaticamente. A escolha de qual token usar em cada requisição é do cliente.
