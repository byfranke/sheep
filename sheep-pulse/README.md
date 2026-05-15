# Sheep Pulse

Sheep Pulse é um produto de Cyber Threat Intelligence sob demanda. Você define um perfil de interesse (tecnologias, países, setores, frameworks). O Pulse consolida a inteligência recente relevante para esse perfil em um briefing estruturado, entregue por e-mail ou webhook.

Use o Pulse quando precisar de um sumário pontual de ameaças e eventos relevantes para o seu ambiente, sem montar pipeline próprio.

## Pré-requisitos

* Conta Sheep com assinatura ativa: Pro, Pro Max, Enterprise, Black Sheep ou Black Sheep Trial.
* E-mail vinculado à sua conta. O mesmo e-mail usado para receber o token da API.

## Como acessar

Acesse o portal em `https://sheep.byfranke.com/pages/pulse-portal.html`.

Clique em "Acessar" e informe o seu e-mail. Você receberá um link mágico no e-mail. Clique para entrar no portal. A sessão dura 24 horas.

Não há senha. Toda autenticação acontece pelo e-mail vinculado.

## Como gerar um Pulse

Dentro do portal, navegue pelas três abas.

1. Aba Perfil. Configure o que interessa: tecnologias usadas, países de operação, setores, frameworks de referência. Salve.
2. Aba Gerar. Clique em "Gerar Pulse". A geração leva alguns segundos. O briefing aparece com sumário executivo, ações urgentes, itens para monitorar e IOCs relevantes.
3. Aba Histórico. Cada Pulse gerado fica salvo. Você pode revisitar ou reenviar para os canais configurados.

## Entrega

Cada Pulse pode ser entregue por dois canais.

Por e-mail. Você recebe um HTML com o briefing formatado no e-mail vinculado à conta.

Por webhook HTTPS. Configure no portal a URL do webhook que recebe o payload JSON do Pulse. Use para integrar com sistemas internos. O Pulse é enviado por POST com Content-Type `application/json`.

Os dois canais podem coexistir. Você pode ter apenas e-mail, apenas webhook, ou ambos.

## Limites por plano

Cada plano define quantos Pulses podem ser gerados em uma janela de tempo e tem limite diário.

* Black Sheep Trial. 1 Pulse no total de avaliação e 1 por dia.
* Black Sheep. Até 5 Pulses por dia, janela de 7 dias.
* Sheep Pro. Até 10 Pulses por dia, janela de 7 dias.
* Sheep Pro Max. Até 30 Pulses por dia, janela de 30 dias.
* Sheep Enterprise. Até 100 Pulses por dia, janela de 30 dias.

Cada Pulse consome aproximadamente 24 mil tokens Sheep da sua quota base. Antes de gerar volume sustentado, confira o saldo em `GET /api/profile`.

## Reenviar um Pulse

No histórico, cada Pulse expõe a opção "Reenviar". O limite é de 5 reenvios por hora por Pulse. Reenvios não consomem quota adicional.

## Boas práticas

Defina o perfil com precisão. Quanto mais específico, mais relevante o briefing. Use a aba Perfil para descrever:

* As principais tecnologias do seu ambiente (cloud, EDR, sistemas críticos).
* Países e regiões de operação.
* Setores que se aplicam ao seu negócio.
* Frameworks de referência (NIST, ISO 27001, MITRE ATT&CK).

Revise o perfil quando o ambiente mudar. Migrações de cloud, fusões e novos negócios afetam o que é relevante para você.

Configure webhook quando quiser ingestão automática. O webhook permite alimentar SIEM, ticketing e dashboards internos sem intervenção humana.

## Auto-envio

Planos Pro Max e Enterprise podem ativar geração automática periódica de Pulses. Configure no portal a frequência desejada. Se a sua quota cair abaixo do necessário para a próxima geração, o auto-envio é pausado automaticamente e você recebe um e-mail informando.

O auto-envio retoma quando o período do plano renova ou quando você contrata um add-on de tokens.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
