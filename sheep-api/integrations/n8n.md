# Integração com n8n

n8n é uma plataforma de automação que conecta serviços via workflows. A Sheep API se integra com n8n através de um nó HTTP padrão.

Esta página descreve o padrão de configuração do nó e dois workflows de exemplo. Os arquivos `.json` dos workflows estão disponíveis em `./n8n-examples/`. Importe direto no seu n8n e ajuste credenciais.

## Padrão do nó HTTP

Para qualquer chamada à Sheep API, configure um nó HTTP Request com os parâmetros abaixo.

* Método. `POST` para `/ai/ask` e `/ai/analyze`. `GET` para `/profile`, `/ai/status`, `/ai/models` e `/feeds/*`.
* URL. Use a URL absoluta. Por exemplo `https://sheep.byfranke.com/api/ai/ask`.
* Headers. Defina exatamente dois headers em chamadas POST:
  * `Content-Type` igual a `application/json`.
  * `X-Sheep-Token` igual ao valor do seu token. Use a feature de credenciais do n8n em vez de hardcoded.
* Body. Em chamadas POST, configure como JSON. Cole o payload no formato esperado pelo endpoint.

A resposta do nó HTTP fica disponível em `{{ $json }}` para os nós seguintes.

## Trabalhar com credenciais

Crie uma credencial do tipo "Header Auth" no n8n com o nome `X-Sheep-Token` e o valor do seu token. Use essa credencial no nó HTTP em vez de digitar o token no campo de header.

Vantagens:

* Token não fica visível no JSON exportado do workflow.
* Rotação do token exige apenas atualizar a credencial, sem reabrir cada nó.

## Workflow 1. Dica diária de segurança

Use este workflow quando quiser publicar uma dica curta de cibersegurança em um canal interno (Discord, Slack, Microsoft Teams) com base no dia da semana.

Estrutura:

1. Nó Schedule Trigger. Dispara uma vez por dia no horário desejado.
2. Nó HTTP Request. Chama `POST /api/ai/ask` com um prompt que pede a dica do dia.
3. Nó de saída (Discord, Slack, etc.) que recebe `{{ $json.response }}` e publica no canal.

O JSON pronto está em `./n8n-examples/sheep-tips.json`.

## Workflow 2. Triagem de alerta SIEM

Use este workflow quando seu SIEM dispara para o n8n via webhook e você quer narrativa automática com sugestão de resposta antes do analista ler.

Estrutura:

1. Nó Webhook. Recebe o payload do alerta do SIEM.
2. Nó HTTP Request. Chama `POST /api/ai/ask` passando o payload do alerta no campo `question` com instrução de papel ("Aja como analista SOC Sênior e analise o alerta a seguir...").
3. Nó de roteamento que decide canal de destino com base na severidade.
4. Nós de saída (ticketing, Discord, e-mail) que enviam `{{ $json.response }}` para os destinatários.

O JSON pronto para alertas Wazuh em nível 15 está em `./n8n-examples/sheep_wazuh_analyst_LV15.json`. O mesmo padrão se aplica a outros SIEMs.

## Boas práticas no n8n

Use o nó "If" depois do HTTP Request para tratar erros. Verifique `{{ $json.success }}` antes de prosseguir. Em falha, encaminhe para um nó de notificação interna.

Configure timeout no nó HTTP. Use 45 segundos para `/ask` e `/analyze` e 15 segundos para os demais.

Adicione um nó "Set" depois do HTTP para extrair apenas os campos que os nós seguintes vão usar. Mantém o payload limpo nos próximos passos.

Em workflows que rodam com alta frequência, monitore o consumo via `GET /api/profile`. Considere adicionar um job semanal que dispara um alerta interno quando o saldo cai abaixo de um percentual configurável.

## Atualização das credenciais

Quando rotacionar o token Sheep pelo Discord, atualize a credencial no n8n. Workflows ativos continuam executando com a credencial antiga até a próxima execução. Programe a rotação em horário de baixa atividade.
