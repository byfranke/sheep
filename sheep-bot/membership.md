# Membership no Bot

Esta página descreve como ativar, consultar e gerenciar sua membership Sheep diretamente pelo Sheep Bot no Discord.

Há três caminhos para entrar em uma membership paga:

* Gift card Black Sheep, ativado por código no bot via `/redeem`.
* Trial gratuito de 3 dias, solicitado via `/trial`.
* Planos contratados na Sheep Store (Pro, Pro Max, Enterprise), vinculados à conta Discord via `/activate`.

## Black Sheep por gift card

Black Sheep é a membership ativada por gift card. Os gift cards estão disponíveis em três durações.

* 3 meses. Código no formato `SB3M-XXXX-XXXX-XXXX`. Concede 90 dias de acesso.
* 6 meses. Código no formato `SB6M-XXXX-XXXX-XXXX`. Concede 180 dias.
* 12 meses. Código no formato `SB12-XXXX-XXXX-XXXX`. Concede 365 dias.

Para ativar, execute no Discord:

```
/redeem code:SB6M-XXXX-XXXX-XXXX
```

O bot valida o código e ativa a membership. A partir desse momento:

* Os limites mensais nos comandos do bot são removidos.
* Você pode configurar feeds pagos com `/blackfeeds`.
* Você pode emitir o token da Sheep API com `/token`.
* O `/membership` mostra a data de expiração.

A renovação acontece por novo resgate de gift card. Códigos podem ser empilhados antes do vencimento atual; o novo prazo soma a partir da data de expiração vigente.

## Trial gratuito

O trial libera 3 dias completos de Black Sheep para avaliação. Disponível uma única vez por conta.

Solicite via:

```
/trial email:usuario@example.com
```

O bot envia um código `SB3D-XXXX-XXXX-XXXX` para o e-mail informado. Resgate o código com `/redeem` para ativar.

O trial dá acesso à Sheep API com quota de 30.000 tokens Sheep no período total. Use para testar integrações antes de comprar um gift card ou um plano.

## Planos pagos da Sheep Store

Planos Pro, Pro Max e Enterprise são contratados na Sheep Store em `https://sheep.byfranke.com/pages/store.html`. O pagamento gera uma assinatura recorrente com cobrança mensal ou anual.

Após o pagamento, a Sheep Store envia um e-mail de confirmação. Este e-mail contém um link de geração de token. Clique para emitir a primeira chave da Sheep API sem precisar abrir o Discord.

Para usar os comandos do bot (`/membership`, `/token`, `/blackfeeds`, Sheep Listener) com os direitos do plano pago, vincule a conta Discord à assinatura. Execute no Discord:

```
/activate email:usuario@example.com
```

Use o mesmo e-mail que você informou no checkout da Sheep Store. O bot inicia um fluxo de verificação por e-mail. Clique no link recebido para concluir a vinculação.

A partir da vinculação:

* O `/membership` reflete o plano contratado, com quota de tokens e modelos liberados.
* `/token` no Discord pode emitir ou rotacionar a chave da Sheep API com os direitos do plano, como alternativa ao link enviado por e-mail.
* Você pode acessar o portal Sheep Pulse no site.

A vinculação fica registrada e sobrevive a rotações de token, trocas de plano e renovações automáticas.

## Consultar status

Para ver seu status corrente:

```
/membership
```

A resposta mostra:

* Tipo de membership (free, trial, Black Sheep, Pro, Pro Max ou Enterprise).
* Data de expiração quando aplicável.
* Tokens consumidos e restantes da Sheep API no período corrente, quando há plano vinculado.
* Add-ons ativos, quando aplicáveis.
* Modelos liberados pelo plano.

Não exige argumentos. Funciona em qualquer servidor onde o Sheep Bot está instalado.

## Caminhos paralelos

Um cliente pode acumular um plano pago e um Black Sheep ativo ao mesmo tempo. Cada um gera um token Sheep API próprio, com quota independente. Em `/membership`, ambos aparecem listados. A escolha de qual token usar em integrações externas é do cliente.

## E-mail vinculado

O e-mail vinculado à sua conta Discord é fixo após a primeira emissão de token. Ele é usado para entregar tokens da Sheep API, briefings do Sheep Pulse e comunicações da Sheep Store.

Alterações de e-mail exigem contato com o suporte oficial em `https://byfranke.com/#Contact`.

## Quando a membership expira

Quando uma membership expira:

* Os comandos do bot voltam a aplicar o limite mensal free.
* Os feeds pagos pausam automaticamente. O canal permanece criado; basta renovar para retomar a publicação.
* O Sheep Listener pausa em canais onde o administrador era o titular da membership.
* O token da Sheep API responde com `402 Payment Required` em chamadas que tentariam consumir quota.

Renovar a membership restaura tudo automaticamente. Não é necessário emitir novo token nem reconfigurar feeds.
