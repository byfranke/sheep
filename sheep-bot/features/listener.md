# Sheep Listener

Sheep Listener é o recurso do Sheep Bot que dá presença ambiente do Sheep dentro de canais do Discord. Em canais com Listener ativo, qualquer membro pode pedir análise direta ao Sheep mencionando o bot ou usando uma palavra-chave configurável. As respostas são cobradas da quota do administrador que ativou o Listener naquele canal, não dos membros.

Use o Listener quando quiser oferecer consulta de cibersegurança aberta para uma equipe sem distribuir tokens individuais.

## Pré-requisitos

* Sheep Bot instalado no servidor Discord.
* Conta Sheep com assinatura ativa para o administrador que vai ativar o Listener. Planos elegíveis: Sheep Plus, Sheep Pro, Sheep Pro Max, Black Sheep ou Black Sheep Trial.
* Sua conta Discord vinculada à conta Sheep (use `/activate` se ainda não vinculou ou `/redeem` para Black Sheep).
* Permissão `Manage Server` (Gerenciar Servidor) no servidor onde o canal está.

## Como ativar

Dentro do servidor Discord, no canal onde você quer ativar o Listener, execute:

```
/listener action:enable
```

A partir desse momento, qualquer mensagem no canal que mencione `@Sheep` recebe resposta inline.

Para desativar:

```
/listener action:disable
```

Para verificar o estado do canal:

```
/listener action:status
```

## Configurar palavra-chave

Por padrão, o Listener responde apenas a menções `@Sheep`. Você pode adicionar uma palavra-chave que também ativa o bot.

```
/listener-keyword keyword:sheep
```

Qualquer mensagem que contenha a palavra configurada ativa resposta. Para remover a palavra-chave, execute o comando com o campo `keyword` vazio.

A palavra-chave aceita até 32 caracteres compostos de letras, números, hifen e underscore.

## Limites por canal

Os limites se aplicam por canal, não por usuário.

* 5 respostas por minuto.
* 100 respostas por dia.
* Até 3 canais ativos por administrador, somando todos os servidores.

Quando o limite por minuto é atingido, mensagens adicionais durante a janela são ignoradas silenciosamente. Quando o limite diário é atingido, o Listener pausa o canal até o início do próximo dia em UTC.

## Cobrança

Cada resposta é cobrada da quota Sheep do administrador que ativou o Listener naquele canal. Membros que fazem perguntas não pagam nada.

O custo de cada resposta sai do saldo de tokens do plano do administrador, conforme as regras de billing da Sheep API. Respostas mais elaboradas consomem mais tokens que respostas curtas. Acompanhe o saldo em `/membership` no Discord.

Quando a quota do administrador acaba, o Listener pausa o canal e publica uma mensagem única indicando upgrade. O canal permanece pausado até o próximo período de billing ou até o saldo voltar a ter folga acima de 5% por meio de add-on.

O sistema verifica a quota a cada 30 minutos. Quando detecta saldo restaurado, retoma o Listener automaticamente e publica "Sheep Listener retomado" no canal.

## Boas práticas

Ative o Listener apenas em canais de pergunta técnica. Em canais de discussão geral, o consumo pode ficar imprevisível.

Estabeleça etiqueta com a equipe. Recomende que perguntas longas ou repetitivas sejam consolidadas. Quanto mais limpa a pergunta, menos tokens são consumidos.

Monitore o consumo via `/membership` no Discord ou via `GET /api/profile` na Sheep API. Considere alertas internos quando o saldo restante cai abaixo de 30% no meio do período.

Se a equipe é grande e o consumo é alto, contrate add-ons em vez de mudar de plano. Add-ons mantêm o mesmo plano-base e somam tokens à quota efetiva.
