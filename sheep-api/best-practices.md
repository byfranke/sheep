# Boas Práticas de Integração

Esta página consolida recomendações operacionais para integrações em produção.

## Segredos

Armazene o token em um gerenciador de segredos. AWS Secrets Manager, HashiCorp Vault, Azure Key Vault e Doppler são opções adequadas. Em containers efêmeros, injete via variável de ambiente.

Não inclua o token em controle de versão. Repositórios privados também são vetor de vazamento por meio de clones, forks e exports. Em caso de exposição, rotacione imediatamente. Assinantes pagos usam o link do e-mail vigente; usuários Black Sheep executam `/token` no Discord.

Configure redaction automática para qualquer string que comece com `shp_` nos logs da sua aplicação. Em frameworks que registram requisições HTTP, redacte explicitamente o header `X-Sheep-Token`.

## Timeouts

Respostas típicas terminam em até 10 segundos. Respostas complexas com modelo Sage podem chegar a 30 segundos. Configure timeout de cliente de 45 segundos.

Timeouts mais curtos cancelam a requisição no cliente mas não impedem o débito da quota quando o servidor já chamou o modelo. Se você precisa de garantia de não débito em caso de timeout, prefira chamadas com modelo Scout, que tem latência menor.

## Retentativa

Aplique retentativa com backoff exponencial apenas a erros transitórios. A política recomendada é três tentativas espaçadas em 2, 5 e 15 segundos.

A lista completa de quais códigos são retentáveis está em `errors.md`.

Para `429 Too Many Requests`, o cabeçalho `Retry-After` é a fonte autoritativa. Implemente fila com paralelismo controlado em vez de hammering com backoff.

## Verificação pré-flight

Antes de despachar lotes grandes de perguntas ou IOCs, consulte `GET /api/profile` e verifique:

* `subscription.status` é `active`.
* `usage.tokens_remaining` cobre o lote estimado com folga.
* `plan.allowed_models` inclui o modelo que você pretende usar.

Despachar 500 chamadas para descobrir no meio que a quota acabou é desperdício de janela operacional.

## Custo por requisição

Toda resposta de `/ask` e `/analyze` traz `tokens_used` com o valor cobrado da quota e `served_by` com o tier que atendeu.

Em integrações de escala, registre esses dois campos por requisição. A soma de `tokens_used` ao longo do período deve bater com `usage.current_period_tokens` em `GET /api/profile`. Divergência sustentada aponta para bug no roteamento do cliente, não na API.

## Idempotência

A API não oferece header de idempotência. Aplicações que precisam dessa garantia (filas com reentrega, jobs com retry distribuído) devem deduplicar no lado cliente antes de chamar a API.

## Compartilhamento de token

Cada token está vinculado a uma única assinatura e tem rate limit próprio. Compartilhar um token entre múltiplas instâncias funciona, mas concentra o limite de taxa em uma fila única.

Para alto paralelismo sustentado, contrate planos Enterprise pelo canal comercial.

## User-Agent

Informe um User-Agent identificável em todas as suas requisições. Padrão sugerido:

```
User-Agent: nome-da-sua-aplicacao/1.0
```

Não é obrigatório, mas facilita diagnóstico quando há contato com o suporte.

## Logging

Para cada chamada à API, registre no mínimo:

* Timestamp UTC.
* Endpoint chamado.
* Status HTTP de retorno.
* `tokens_used` quando bem-sucedido.
* `served_by` quando bem-sucedido.

Não registre o corpo da resposta inteiro a menos que isso seja requisito do seu controle interno. Registre apenas o que ajuda em diagnóstico.

## Tratamento de IOCs sensíveis

Em `/api/ai/analyze`, o parâmetro `enrich` controla consulta a fontes externas de reputação. Para IOCs internos que não devem sair da sua organização, envie `"enrich": false`. A resposta nesse modo se baseia apenas no conhecimento do modelo, sem reputação externa.

Use `enrich: false` também quando o objetivo for narrativa pura sem custo de enriquecimento adicional.
