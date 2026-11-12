# Sheep Pulse

Sheep Pulse é um produto de Cyber Threat Intelligence sob demanda. Você define um perfil de interesse (tecnologias, países, setores, frameworks). O Pulse consolida a inteligência recente relevante para esse perfil em um briefing estruturado, entregue por e-mail ou webhook.

Use o Pulse quando precisar de um sumário pontual de ameaças e eventos relevantes para o seu ambiente, sem montar pipeline próprio.

## Pré-requisitos

* Conta Sheep com assinatura ativa: Sheep Plus, Sheep Pro, Sheep Pro Max, Black Sheep ou Black Sheep Trial.
* E-mail vinculado à sua conta. O mesmo e-mail usado para receber o token da API.

## Como acessar

O Pulse fica na Sheep Platform, no módulo Pulse: `https://sheep.byfranke.com/app#pulse`. Entre com o e-mail vinculado à conta: você recebe um link de acesso por e-mail, sem senha. O endereço antigo `https://sheep.byfranke.com/pages/pulse-portal` leva para o mesmo lugar. Detalhes do login e da sessão em `sheep-platform/README.md`.

## Como gerar um Pulse

O módulo Pulse tem duas abas: Briefing e Radar. Na aba Briefing:

1. Abra a engrenagem ao lado de "Gerar Pulse" e preencha o perfil: tecnologias usadas, países de operação, setores e frameworks de referência. Salve.
2. Escolha a janela de dias e clique em "Gerar Pulse". A geração leva alguns segundos. O briefing aparece com sumário executivo, ações urgentes, itens para monitorar e IOCs relevantes.
3. Cada Pulse fica em "Seus Pulses", para abrir de novo ou baixar em PDF. O sino do console avisa quando um Pulse fica pronto.

## Entrega

Cada Pulse pode ser entregue por dois canais.

Por e-mail. Você recebe um HTML com o briefing formatado no e-mail vinculado à conta.

Por webhook HTTPS. Configure no perfil (engrenagem) a URL do webhook que recebe o payload JSON do Pulse. Use para integrar com sistemas internos. O Pulse é enviado por POST com Content-Type `application/json`.

Os dois canais podem coexistir. Você pode ter apenas e-mail, apenas webhook, ou ambos.

## Limites por plano

Os limites contam numa janela móvel de 24 horas.

* Black Sheep Trial. 1 Pulse no total, com janela de até 3 dias.
* Black Sheep. 1 Pulse por dia, com janela de até 30 dias.
* Sheep Plus. 1 Pulse por dia, com janela de até 30 dias.
* Sheep Pro. Até 30 Pulses por dia, com janela de até 30 dias.
* Sheep Pro Max. Até 50 Pulses por dia, com janela de até 30 dias.

A janela é o número de dias de feeds que o briefing considera. O padrão é 7 dias. No console, o cartão de uso do Pulse mostra quantos você já gerou e o que o plano seguinte libera.

Cada Pulse consome aproximadamente 24 mil tokens Sheep da sua quota base. Antes de gerar volume sustentado, confira o saldo em `GET /api/profile`.

## Reenviar um Pulse

Pela Sheep API, com o token da conta, `POST /api/pulse/{pulse_id}/resend` reenvia um Pulse do histórico para os canais configurados. O limite é de 5 reenvios por hora por Pulse. Reenvios não consomem quota adicional.

## Boas práticas

Defina o perfil com precisão. Quanto mais específico, mais relevante o briefing. Use o perfil (engrenagem na aba Briefing) para descrever:

* As principais tecnologias do seu ambiente (cloud, EDR, sistemas críticos).
* Países e regiões de operação.
* Setores que se aplicam ao seu negócio.
* Frameworks de referência (NIST, ISO 27001, MITRE ATT&CK).

Revise o perfil quando o ambiente mudar. Migrações de cloud, fusões e novos negócios afetam o que é relevante para você.

Configure webhook quando quiser ingestão automática. O webhook permite alimentar SIEM, ticketing e dashboards internos sem intervenção humana.

## Envio automático

O envio automático gera e entrega o Pulse sozinho: todos os dias, a cada 3 dias ou uma vez por semana. Para ligar, abra a engrenagem ao lado de "Gerar Pulse", marque "Gerar e enviar o Pulse sozinho", escolha a frequência e salve. O Pulse usa o perfil e a janela salvos e sai pelos canais marcados (e-mail, webhook ou os dois). O primeiro envio sai em até 1 hora.

Vale em todos os planos pagos, dentro do limite de Pulses do plano: cada envio automático conta nesse limite. No Sheep Plus e no Black Sheep, que geram 1 Pulse por dia, o envio automático diário usa esse Pulse do dia. Se você já gerou o Pulse do dia, o envio espera o limite liberar. No teste, que tem 1 Pulse no total, o envio automático aparece trancado.

Se a sua quota cair abaixo do necessário para a próxima geração, o envio automático pausa sozinho e você recebe um aviso por e-mail e no sino do console. Ele volta quando o período do plano renova ou, no Sheep Pro e no Sheep Pro Max, quando você contrata um add-on de tokens.

Pela Sheep API, com o token da conta, o mesmo ajuste fica em `PUT /api/pulse/profile` (`auto_send_enabled` e `auto_send_interval`: `daily`, `every_3_days` ou `weekly`). O `PUT` substitui o perfil inteiro: leia antes com `GET /api/pulse/profile`. No teste, ligar o envio automático retorna `403` com código `auto_send_not_in_plan`.

## Radar: monitoramento do domínio

Na aba Radar do Pulse, a Sheep monitora a exposição dos domínios da sua empresa na internet, com nota de A a F e aviso por e-mail quando a nota piora. Detalhes em `sheep-pulse/radar.md`.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
