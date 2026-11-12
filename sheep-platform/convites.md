# Convites

Convites permitem indicar a Sheep para outras pessoas com um link pessoal. Quando um convidado ativa o trial ou assina um plano pago pelo seu link, você ganha tokens bônus no seu plano.

O link de convite fica no módulo Conta da Sheep Platform.

## Pré-requisitos

* Um plano pago ativo: Sheep Plus, Sheep Pro, Sheep Pro Max ou Black Sheep (ativado pelo site ou pelo Discord).
* Acesso à Sheep Platform em `https://sheep.byfranke.com/app`, com o mesmo e-mail do plano.

O plano Black Sheep Trial e o período de avaliação de um plano pago não geram link de convite. Um plano com cancelamento agendado também não.

## Como convidar

1. Acesse `https://sheep.byfranke.com/login` e entre com o e-mail do seu plano.
2. Abra o módulo Conta e localize a seção Convites.
3. Clique em "Copiar link".
4. Envie o link para a pessoa que você quer convidar.

O link tem este formato:

```
https://sheep.byfranke.com/pages/convite?c=CODIGO_DO_CONVITE
```

Cada conta tem um único link ativo. O link não expira.

## Bônus

Você recebe tokens bônus quando o convidado conclui uma destas ações pelo seu link:

* Ativa o trial de 3 dias: você recebe 15.000 tokens bônus.
* Assina um plano pago: você recebe 150.000 tokens bônus. Vale a compra de um plano na Sheep Store ou a ativação de um Gift Card Black Sheep pelo site.

O convidado tem 30 dias, contados a partir do registro do e-mail na página do convite, para ativar o trial. Para o bônus de assinatura, o prazo é de 30 dias a partir do trial ou, sem trial, a partir do registro. Se o convidado ativar o trial e assinar dentro dos prazos, você recebe os dois bônus.

### Quando o bônus é creditado

* Trial: o crédito acontece em alguns minutos depois que o convidado ativa o trial.
* Assinatura: o crédito acontece 7 dias depois do primeiro pagamento confirmado do convidado. Se o convidado desistir da compra nesse prazo, o bônus não é creditado.

### Onde o bônus entra

Os tokens bônus somam à cota do período de cobrança em curso do seu plano e vencem com ele, como um gift card convertido em tokens. Eles aparecem em Conta > Plano e uso, no card Tokens bônus, identificados como "Convite (trial)" ou "Convite (assinatura)". Valem em todas as superfícies que debitam da mesma cota: Platform, API, CLI, MCP e Sheep Bot.

Se você tem mais de um plano no mesmo e-mail, o bônus entra no plano de maior nível, o mesmo que a Platform usa para cobrar.

Um bônus creditado a menos de 7 dias da renovação vale já e também no período seguinte inteiro, para não se perder. Nesse caso o card mostra até quando ele vale.

O seu plano precisa estar ativo no momento do crédito. Se o plano estiver vencido ou cancelado, o bônus não é aplicado.

### Limites

* Até 5 bônus de trial por mês.
* Até 1.500.000 tokens de bônus por ano, somando trials e assinaturas.

Os limites contam por mês e por ano do calendário. Quando um bônus passa do limite anual, você recebe apenas os tokens que ainda cabem nele. Depois de atingir um limite, o seu link continua funcionando para os convidados, mas os novos convites não geram bônus até o limite renovar.

### Quem conta como convidado

O bônus vale somente para pessoas novas na Sheep:

* O bônus de trial vale para e-mails que nunca usaram o trial.
* O bônus de assinatura vale para e-mails que nunca tiveram um plano pago.
* Convites para o seu próprio e-mail não geram bônus.

Por privacidade, a Sheep não informa se um convidado já foi cliente. Um convite para um e-mail que já usou o trial ou já teve plano pago aparece como Aguardando e, ao fim do prazo, como Expirado, da mesma forma que um convite sem ativação.

Cada pessoa fica associada ao primeiro link pelo qual registrou o e-mail. Se ela não ativar nada dentro do prazo, o registro expira e um novo convite pode ser registrado.

## Acompanhar seus convites

A seção Convites, no módulo Conta, mostra:

* O link ativo.
* Os tokens de bônus recebidos no ano e os bônus de trial do mês.
* A lista de convidados, com o e-mail parcialmente oculto e a situação do trial e da assinatura de cada um.

Situações possíveis:

`Aguardando`
: O convidado registrou o e-mail e ainda não gerou bônus dentro do prazo.

`Pendente`
: A assinatura do convidado está dentro dos 7 dias iniciais. A tela mostra a data prevista do crédito.

`Creditado`
: Os tokens já entraram no seu plano. A tela mostra quantos.

`Não elegível`
: O convite foi para o seu próprio e-mail, o limite foi atingido, o seu plano não estava ativo no momento do crédito ou o convidado desistiu da compra no prazo de 7 dias. A tela mostra o motivo.

`Expirado`
: O prazo terminou sem bônus. Isso inclui convites para e-mails que já usaram o trial ou já tiveram plano pago.

Convites que terminaram sem bônus saem da lista 6 meses depois do registro.

## Gerar um novo link

Se o seu link circulou onde você não queria, gere outro:

1. No módulo Conta, abra a seção Convites.
2. Clique em "Gerar novo link" e confirme.

O link anterior para de funcionar na hora. Convites já registrados continuam valendo e os bônus pendentes são mantidos. Depois de gerar um link, aguarde alguns minutos para gerar outro.

## Para quem recebeu um convite

1. Abra o link recebido.
2. Informe o e-mail que você vai usar na Sheep e clique em "Continuar".
3. Escolha uma opção:
   * "Começar trial grátis": abre o pedido do trial de 3 dias com o seu e-mail preenchido. O código chega por e-mail. Ative o código em `https://sheep.byfranke.com/pages/redeem` com o mesmo e-mail.
   * "Ver planos": abre a Sheep Store. Conclua a compra com o mesmo e-mail.

Use o mesmo e-mail em todas as etapas. Uma ativação ou compra feita com outro e-mail não fica associada ao convite.

Você não vê o e-mail de quem convidou. Quem convidou vê o seu e-mail parcialmente oculto.

## Uso indevido

Criar contas falsas ou usar e-mails próprios para gerar bônus leva à remoção dos bônus e à desativação do link.

As regras do programa podem mudar. Bônus já creditados não são afetados por mudanças futuras.

## Solução de problemas

`A seção Convites não aparece em Conta`
: O seu plano é Black Sheep Trial, está em período de avaliação, tem cancelamento agendado ou não está ativo. Convites exigem um plano pago ativo.

`O convidado vê a mensagem "Este convite não é válido"`
: O link está incompleto ou foi substituído por um novo. Copie o link atual na seção Convites e envie de novo.

`O convidado não consegue ativar o trial`
: O trial é limitado a um por e-mail. Um e-mail que já usou o trial não gera bônus de trial. Se ele nunca teve plano pago, a assinatura pelo seu link ainda gera o bônus de assinatura.

`O bônus não apareceu depois da assinatura do convidado`
: O crédito de assinatura acontece 7 dias após o primeiro pagamento confirmado. Até lá, o convite aparece como Pendente. Confirme também se o convidado usou o mesmo e-mail informado na página do convite.

`O convite está como Creditado, mas a cota não mudou`
: Veja o card Tokens bônus em Conta > Plano e uso. Um bônus creditado perto da renovação vale já e também no período seguinte, e o card mostra até quando.

`O bônus aparece como Não elegível`
: Consulte o motivo exibido ao lado da situação. Esses casos não geram tokens de bônus.

`O convidado assinou, mas o convite terminou como Expirado`
: O e-mail do convidado já tinha usado o trial ou já tinha um plano pago antes do convite, ou a compra foi feita com outro e-mail. Esses casos não geram bônus.

`O meu plano venceu antes do crédito`
: Bônus não são aplicados a planos vencidos. Renove o plano para voltar a receber o bônus dos próximos convites.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
