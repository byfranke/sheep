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

Gift card de 3, 6 ou 12 meses, resgatado no site (`https://sheep.byfranke.com/pages/redeem`) ou no Discord com `/redeem`.

Teto: 167.000 tokens Sheep por mês de duração. Um gift card de 6 meses libera 1.000.000 tokens no período total.

Modelos liberados: `auto`, `scout`, `hunter`.

### Black Sheep Trial

Identificador: `black_sheep_trial`

Avaliação de 3 dias, sem cartão, pedida no site (`https://sheep.byfranke.com/pages/trial`) ou no Discord com `/trial`. Uma por e-mail.

Teto: 30.000 tokens Sheep no período total.

Modelos liberados: `auto`. No teste a Sheep escolhe o modelo sozinha (Scout 8B ou Hunter 17B, conforme a pergunta). Pedir `scout`, `hunter` ou `sage` explicitamente retorna `403 Forbidden` com código `model_not_in_plan`.

## Comparação dos planos

| | Teste | Black Sheep | Sheep Plus | Sheep Pro | Sheep Pro Max |
|---|---|---|---|---|---|
| Tokens | 30 mil nos 3 dias | 500 mil, 1 milhão ou 2 milhões (gift card de 3, 6 ou 12 meses) | 300 mil por mês | 1 milhão por mês | 4 milhões por mês |
| Modelos | `auto` | `auto`, Scout 8B, Hunter 17B | `auto`, Scout 8B, Hunter 17B | `auto`, Scout 8B, Hunter 17B, Sage 120B | `auto`, Scout 8B, Hunter 17B, Sage 120B |
| Ritmo semanal da cota | não | sim | sim | não | não |
| Add-ons de tokens | não | não | não | sim | sim |
| Pulses | 1 no total | 1 por dia | 1 por dia | 30 por dia | 50 por dia |
| Janela de feeds do Pulse | até 3 dias | até 30 dias | até 30 dias | até 30 dias | até 30 dias |
| Envio automático do Pulse | não | sim | sim | sim | sim |
| Sheep Agent no Ask (Sheep Platform) | não | não | não | sim | sim |
| Domínios no Radar | nenhum | 1 | 1 | 5 | 20 |
| Voz Sheep | não | sim | sim | sim | sim |
| Gift card vira tokens bônus | não | não | não | sim | sim |
| Bônus de convite | não | sim | sim | sim | sim |

Em todos os planos, inclusive no teste: a Sheep Platform com todos os módulos (Dashboard, Ask, Analyze, DFIR, Pulse, Feeds, Ransomware Intel, Recursos e Integrações), a Sheep API, o Sheep MCP e a Sheep CLI, com o mesmo token e a mesma cota. Os Pulses por dia contam numa janela móvel de 24 horas. Na Sheep Platform, o que o plano não inclui continua à vista, trancado, com o plano que libera e o link da Sheep Store.

## Add-ons

Planos Sheep Pro (identificador `pro_max`) e Sheep Pro Max (identificador `enterprise`) aceitam add-ons recorrentes que ampliam o teto mensal sem mudar de plano. Os add-ons disponíveis hoje:

* `tokens_2m` adiciona 2.000.000 tokens Sheep por mês.
* `tokens_4m` adiciona 4.000.000 tokens Sheep por mês.

Um cliente pode ter mais de um add-on ativo ao mesmo tempo. O teto efetivo do período é o teto do plano somado a todos os add-ons ativos. A composição completa aparece em `GET /api/profile`.

## Gift card como tokens bônus (Sheep Pro e Sheep Pro Max)

Um gift card Black Sheep (3, 6 ou 12 meses) resgatado por uma conta Sheep Pro ou Sheep Pro Max não dá um segundo acesso: na Sheep Platform, em Conta > Plano e uso > "Adicionar tokens com gift card", o código é convertido em tokens bônus do período de cobrança atual. Valores: 3 meses, 500.000 tokens; 6 meses, 1.000.000; 12 meses, 2.000.000. Os tokens bônus somam à cota do período, aparecem à parte na Conta (com um trecho do código) e vencem com o período. Ao converter, o cliente aceita que o código não dá acesso Black Sheep, cargo no Discord nem feeds pagos, e que não há estorno. Códigos de teste não são convertidos. Um código convertido a menos de 7 dias da renovação vale já e também no período seguinte inteiro, para não se perder. O card da Conta leva à seção de gift cards da loja. `GET /api/profile` mostra o valor em `usage.bonus_token_budget`.

## Bônus de convite (todos os planos pagos)

Quem tem Sheep Plus, Sheep Pro, Sheep Pro Max ou Black Sheep ativo recebe tokens bônus quando um convidado ativa o trial (15.000 tokens) ou assina um plano pago (150.000 tokens, creditados 7 dias após o primeiro pagamento) pelo seu link de convite, com limites de 5 bônus de trial por mês e 1.500.000 tokens por ano. O bônus entra no período de cobrança em curso do plano de maior nível do e-mail, aparece no mesmo card Tokens bônus da Conta e vence com o período; a menos de 7 dias da renovação vale também no período seguinte. Regras completas em `sheep-platform/convites.md`.

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

## Ritmo semanal (Sheep Plus e Black Sheep)

Os planos de entrada liberam a cota do período em parcelas semanais, para que ela dure o período inteiro em vez de acabar nos primeiros dias. A parcela é proporcional: no Sheep Plus (300.000 tokens em 30 dias) são cerca de 70.000 por semana; no Black Sheep de 3 meses (500.000 em 90 dias), cerca de 39.000. O que não foi usado numa semana fica disponível nas seguintes.

Ao chegar à parcela liberada até ali, as chamadas às ferramentas de IA respondem `402 Payment Required` com código `weekly_limit_reached`, informando `allowed_now`, `weekly_allowance`, `next_window_at` (quando a próxima parcela libera) e `continue_url`. Na Sheep Platform, o mesmo aviso aparece como uma caixa de confirmação: você pode liberar o restante do período na hora (uma confirmação por período, válida para a API, a CLI, o MCP e a Platform) ou fazer upgrade com desconto usando o cupom `UPGRADE40`. O upgrade vale assim que o pagamento é confirmado: a Platform passa a usar o plano novo e o token da API do plano novo chega por e-mail.

Perto de 95% da cota do período, você recebe um e-mail avisando, uma vez por período. O Sheep Pro, o Sheep Pro Max e o período de avaliação não têm ritmo semanal. `GET /api/profile` expõe o estado em `pacing` (`enabled`, `allowed_now`, `next_window_at`, `acknowledged`).

## Estouro de quota

A API impede consumo além do teto. Antes de cada chamada à IA, o servidor estima o custo mínimo e verifica saldo. Se não cobrir, a chamada é rejeitada com `402 Payment Required` e código `quota_exhausted`. Não há débito sem geração de resposta.

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
