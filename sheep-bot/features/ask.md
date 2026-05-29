# Sheep Ask

`/ask` é o comando de conversação livre do Sheep Bot. Envia uma pergunta de cibersegurança em linguagem natural e recebe a resposta inline no Discord.

Use `/ask` quando o objetivo é entender um conceito, perfilar um ator de ameaças, explicar uma técnica MITRE, narrar logs colados na própria pergunta ou pedir orientação sobre um caso. Para um IOC isolado com saída estruturada, prefira `/analyze`.

## Quem pode usar

Acesso público. Funciona em qualquer servidor onde o Sheep Bot está instalado.

Membros free têm limite de 10 execuções por mês. O contador zera no primeiro dia de cada mês UTC.

Membros Black Sheep, Sheep Plus, Sheep Pro e Sheep Pro Max não têm limite mensal de execuções no Discord. O `/ask` no Discord não consome tokens da quota da Sheep API do plano, independentemente do vínculo via `/activate`.

## Argumentos

O bot apresenta o slash command no Discord com um único campo:

* `question`. Pergunta em linguagem natural. Texto livre, de 3 a 2500 caracteres. Aceita português e inglês.

A escolha do tier de IA é feita automaticamente pelo bot conforme a complexidade detectada na pergunta. Não há seleção manual de modelo no Discord. Para escolher o tier explicitamente, use a Sheep API via HTTP ou as ferramentas de linha de comando do Sheep CLI.

## Tier de IA atribuído

O bot roteia internamente entre dois tiers conforme a pergunta:

* Tier rápido. Atende perguntas curtas, definições e checagens factuais.
* Tier analítico. Atende perfis de APT, explicação de frameworks, análise multi-IOC e narração sobre logs.

O tier que atendeu a requisição aparece no rodapé da resposta, como referência.

O tier profundo (Sage) não é selecionável pelo bot. Acesse-o pelo `POST /api/ai/ask` na Sheep API quando seu plano cobrir o modelo (Sheep Pro ou Sheep Pro Max).

## Exemplos de uso

Pergunta simples:

```
/ask question:O que é o framework MITRE ATT&CK?
```

Pergunta analítica:

```
/ask question:Quais técnicas TTP do APT29 estão associadas a ataques contra cloud?
```

Pergunta com log colado:

```
/ask question:Analise este alerta do firewall e diga se é ataque ou ruído. 2026-05-10 14:22:11 BLOCK 198.51.100.4 -> 10.0.0.5:445 SMB
```

Pergunta com pedido de framework explícito:

```
/ask question:Faça correlação entre os três incidentes que reportei esta semana e descreva no formato Diamond Model.
```

No Discord, o slash command abre o campo de entrada `question` automaticamente. Cole o texto e envie. Não há outros campos.

## O que esperar na resposta

O bot responde inline no canal com:

* Texto narrativo formatado em Markdown.
* Indicação do tier que atendeu a requisição no rodapé.
* Tempo de geração.

O uso do `/ask` no Discord não debita tokens da quota da Sheep API. O contador relevante é o limite mensal de execuções por usuário, verificável em `/membership`. A quota de tokens do plano é consumida apenas em chamadas diretas à Sheep API e nas integrações que usam token pago (Sheep CLI e Sheep Web).

## Idiomas

A pergunta pode ser em português, inglês ou outro idioma. A resposta é gerada no idioma da pergunta. Para forçar idioma específico, mencione no próprio texto: "Responda em português."

A preferência permanente de idioma do bot é configurada com `/language` e afeta mensagens de sistema (erros, confirmações), não o conteúdo da resposta de `/ask`.

## Limites e tratamento de erros

Pergunta com menos de 3 caracteres ou acima de 2500 caracteres. O bot rejeita antes de consumir cota. Reformule a pergunta dentro do limite.

Pergunta vazia ou só com pontuação. Mesma rejeição.

Quota mensal esgotada (free). O bot responde com mensagem clara indicando upgrade ou aguardar a virada do mês. Não consome cota.

Em planos pagos não há esgotamento de saldo aplicável ao `/ask` no Discord, pois o comando não consome tokens da Sheep API. Em chamadas diretas à Sheep API com token pago, a resposta indica saldo insuficiente quando aplicável.

Falha transitória no serviço de IA. O bot orienta a tentar novamente em alguns segundos. Não consome cota nem tokens.

## Quando usar `/analyze` em vez de `/ask`

Use `/analyze` quando você tem um IOC específico para investigar (IP, domínio, hash, URL, CVE) e quer saída estruturada com verdito, score de risco, tags e recomendações. Veja `analyze.md`.

Use `/ask` quando você tem uma pergunta em texto livre, mesmo que ela contenha IOCs no meio. O bot enriquece automaticamente o prompt com contexto de reputação quando detecta IOCs na pergunta.
