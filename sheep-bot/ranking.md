# Ranking

Sheep Bot tem um sistema de progressão por XP que recompensa uso ativo dos comandos de análise e investigação. Cada ação consome experiência e contribui para subir de nível e desbloquear ranks superiores.

O ranking é por usuário e funciona em qualquer servidor onde o bot está instalado. Seu rank acompanha sua conta Discord, não o servidor.

## Como ganhar XP

Os comandos de análise e investigação concedem XP quando executados com sucesso:

* `/analyze`. 10 XP por execução bem-sucedida.

Comandos auxiliares de cibersegurança concedem 2 XP cada por execução bem-sucedida.

Execuções com erro ou que não retornam resultado não dão XP.

## Ganho de XP por tipo de conta

Usuários free têm limite de dez execuções por mês em cada comando que concede XP. Quando o limite é atingido, o comando é bloqueado antes de executar e nenhuma XP é creditada. O teto natural de ganho mensal de um usuário free é de aproximadamente 220 XP, somando as dez execuções de `/analyze` e as dez execuções dos comandos auxiliares.

Membros Black Sheep, Sheep Plus, Sheep Pro e Sheep Pro Max não têm limite mensal de execuções. Toda execução bem-sucedida credita XP, sem teto mensal. O ritmo de progressão acompanha o volume real de uso.

## Fórmula de nível

A quantidade de XP necessária para o próximo nível segue uma curva quadrática. Quanto mais alto o nível, maior a XP exigida.

A fórmula é: XP para o próximo nível igual a 5 multiplicado pelo quadrado do nível atual.

Exemplos:

* Nível 1 para 2. 5 XP.
* Nível 5 para 6. 125 XP.
* Nível 10 para 11. 500 XP.

## Ranks

Os ranks evoluem conforme o nível. As faixas em ordem crescente:

* Rank Analyst L1. Níveis 1 a 2.
* Rank Analyst L2. Níveis 3 a 5.
* Rank Analyst L3. Níveis 6 a 9.
* Rank Specialist L1. Níveis 10 a 14.
* Rank Specialist L2. Níveis 15 a 19.
* Rank Specialist L3. Níveis 20 a 24.
* Rank Sheep Architect. Nível 25 em diante.

Quando você sobe de rank, o bot envia uma mensagem direta confirmando a transição e atualiza o cargo no servidor oficial Sheep Community.

## Bônus por rank

Algumas transições de rank concedem dias gratuitos de Black Sheep ao usuário, creditados automaticamente na primeira vez que o rank é atingido. Recuperar um rank após decaimento de XP não repaga o bônus.

* Rank Analyst L2. 1 dia de Black Sheep.
* Rank Specialist L1. 3 dias de Black Sheep.
* Rank Specialist L3. 7 dias de Black Sheep.
* Rank Sheep Architect. Cargo permanente Architect na Sheep Community, sem dias adicionais de membership.

## Como consultar seu rank

Execute o comando dentro de qualquer servidor onde o bot está presente:

```
/rank
```

A resposta exibe seu nível atual, XP acumulada, XP necessária para o próximo nível e o rank vigente.

## Sincronização de cargos

Na comunidade oficial Sheep Community no Discord, ranks são refletidos automaticamente como cargos no servidor. O cargo é atualizado quando você sobe de rank.

Em outros servidores onde o Sheep Bot está presente, os ranks ficam visíveis apenas via `/rank`, sem sincronização de cargos.

## Boas práticas

Use `/analyze` quando quiser maximizar o ganho. É o comando que concede mais XP por execução.

Use o bot conforme sua necessidade real de análise. Em contas free, execuções sem propósito esgotam o limite mensal antes da hora. Em contas pagas, o uso é livre, mas execuções vazias não agregam valor operacional ao seu trabalho.

Subir de rank não dá acesso a comandos pagos. Os benefícios pagos vêm pela membership Black Sheep ou planos Sheep Plus, Sheep Pro e Sheep Pro Max. Ranks são reconhecimento de atividade técnica continuada.
