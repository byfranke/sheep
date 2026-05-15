# Workflows n8n de Exemplo

Esta pasta reúne workflows prontos para n8n. Importe direto no seu n8n via Workflows -> Import from File.

## sheep-tips.json

Workflow agendado que gera uma dica diária de cibersegurança e publica em um canal Discord.

Como usar:

1. Importe `sheep-tips.json` no n8n.
2. Substitua o placeholder `INSERIR_SEU_TOKEN_AQUI` no nó "Sheep AI API" pelo valor do seu token Sheep. Recomenda-se substituir por uma credencial "Header Auth" do n8n com nome `X-Sheep-Token`.
3. Substitua `INSERIR_GUILD_ID` e `INSERIR_CHANNEL_ID` no nó Discord pelos identificadores do seu servidor e canal.
4. Ative o workflow. O horário padrão é configurado no nó Schedule Trigger; ajuste conforme preferência.

O prompt é construído dinamicamente conforme o dia da semana, com temas diferentes por dia.

## sheep_wazuh_analyst_LV15.json

Workflow acionado por webhook que recebe alertas Wazuh de nível 15 e gera narrativa de SOC com sugestão de resposta.

Como usar:

1. Importe `sheep_wazuh_analyst_LV15.json` no n8n.
2. Substitua o placeholder `INSIRA-NOME-DO-WEBHOOK` no nó Webhook pelo caminho desejado.
3. Substitua `INSERIR_SEU_TOKEN_SHEEP_AQUI` no nó "Sheep AI API" pelo valor do seu token Sheep ou use credencial do n8n.
4. Configure o Wazuh para enviar alertas para a URL pública do webhook. Use o bloco `<integration>` no `ossec.conf` conforme documentação do Wazuh para integrações customizadas via webhook HTTP.
5. Ative o workflow. Cada alerta de nível 15 que chegar ao webhook dispara uma chamada à Sheep API e roteia a resposta para os destinatários configurados nos nós seguintes.

O mesmo padrão se aplica a outros SIEMs que suportam envio por webhook HTTP, como Elastic, Splunk e CrowdStrike. Ajuste apenas o nó Webhook e o formato esperado de `$json.body` no prompt.
