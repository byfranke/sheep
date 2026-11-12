# Proteção contra golpe de contas invadidas

O Sheep Bot protege os servidores onde está instalado contra o golpe das quatro imagens: o cassino de cripto com prêmio falso que contas invadidas postam em todos os canais que alcançam, muitas vezes com `@everyone`. As imagens costumam ser um post falso de uma celebridade anunciando o cassino, a tela de um código promocional e capturas de "saque concluído".

Quem posta não é o dono da conta. O token da conta foi roubado, em geral por um programa malicioso, e um script usa a conta para espalhar o golpe. Por isso a proteção nunca expulsa nem bane ninguém.

## O que o bot faz

Quando reconhece o golpe, o Sheep Bot:

* Apaga a mensagem e as cópias da mesma mensagem em outros canais do servidor.
* Aplica um castigo (timeout) de 7 dias na conta, para parar os envios automáticos. O membro continua no servidor.
* Envia ao membro, por DM, o passo a passo para recuperar a conta.
* Envia ao dono do servidor, por DM, um aviso do que foi feito. Se o dono não aceitar DMs, o aviso vai para o canal de alertas de segurança ou de atualizações da comunidade, quando o servidor tem um.

## Como o golpe é reconhecido

O bot olha só mensagens com imagens. Ele age quando a mensagem segue o padrão do golpe, por exemplo várias imagens com tentativa de `@everyone` ou `@here`, as mesmas imagens postadas em vários canais em poucos minutos, imagens idênticas às de um golpe já bloqueado no mesmo servidor, ou uma conta que acabou de ser pega com o mesmo golpe em outro servidor.

Membros da equipe do servidor (quem tem permissão de moderação), bots e webhooks nunca são afetados.

## Comando para a equipe

Quando um golpe passa sem ser reconhecido, quem pode moderar membros trata a mensagem com um clique:

1. Clique com o botão direito na mensagem.
2. Escolha `Apps`.
3. Escolha `Golpe: conta invadida` (em clientes em inglês, `Scam: hijacked account`).

O bot apaga a mensagem, aplica o castigo, avisa o membro e passa a reconhecer as mesmas imagens naquele servidor.

## Permissões

Para agir, o Sheep Bot precisa das permissões `Gerenciar mensagens` e `Moderar membros`, e o cargo dele precisa ficar acima dos cargos dos membros. Sem elas, o bot avisa o dono do servidor do que viu e de quais permissões faltam.

Para desligar a proteção num servidor, retire do bot essas duas permissões.

## Falso positivo

Se a conta de alguém foi castigada por engano, ou se a pessoa já recuperou a conta, qualquer moderador pode tirar o castigo antes do prazo: botão direito no membro, `Remover castigo`.

## Se a sua conta foi invadida

1. Troque a senha do Discord. Isso desconecta o token roubado.
2. Ative a autenticação em dois fatores.
3. Em `Configurações > Dispositivos`, saia de todos os dispositivos que você não reconhece.
4. Em `Configurações > Aplicativos autorizados`, remova o que você não reconhece.
5. Passe um antivírus no computador. O roubo de token costuma vir de arquivos, jogos ou extensões falsas.
6. Avise seus amigos. A mesma mensagem pode ter chegado a eles.

Ajuda oficial do Discord: `https://support.discord.com/hc/pt-br/articles/24160905919511`

## Privacidade

O bot só verifica mensagens com imagens. De um golpe confirmado guardamos apenas a impressão digital (hash) das imagens, por 30 dias e só no servidor onde ele aconteceu, e o registro do incidente por 90 dias. O conteúdo das mensagens não é guardado. Detalhes na política de privacidade: `https://sheep.byfranke.com/pages/privacy`
