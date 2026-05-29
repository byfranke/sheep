# Getting Started

Este guia leva você do zero ao primeiro retorno bem-sucedido da Sheep API em menos de cinco minutos.

## 1. Adquira uma assinatura

A Sheep API atende contas com assinatura ativa. As opções são:

* Sheep Plus, Sheep Pro e Sheep Pro Max. Contratados na Sheep Store em `https://sheep.byfranke.com/pages/store.html`.
* Black Sheep. Resgate por gift card de 3, 6 ou 12 meses, ativado dentro do Discord.
* Black Sheep Trial. Acesso de 3 dias para avaliação, ativado pelo Discord.

O plano gratuito comum não dá acesso à API. Apenas os planos acima emitem token.

## 2. Emita seu token de API

Há dois caminhos para emitir o token, conforme o seu tipo de assinatura.

### Sheep Plus, Sheep Pro e Sheep Pro Max

O primeiro e-mail enviado pela Sheep Store após a confirmação da assinatura traz um link de geração de token. Clique no link, confirme sua identidade e o token será entregue por e-mail.

Esse é o caminho recomendado para assinantes pagos. Não é necessário entrar no Discord para emitir a primeira chave.

Se você perdeu o e-mail inicial, vincule sua conta Discord à assinatura com `/activate` no Discord (informando o mesmo e-mail do checkout) e em seguida use `/token` para emitir.

### Black Sheep e Black Sheep Trial

A emissão acontece dentro do Discord. Acesse `https://sheep.byfranke.com/discord` e entre no servidor da comunidade.

Execute o comando:

```
/token
```

O bot pede confirmação do e-mail vinculado à sua conta. Confirme. O token é entregue por e-mail.

### Em ambos os caminhos

O token nunca é exibido em tela. A entrega exclusivamente por e-mail protege contra exposição acidental em screenshots, gravações de tela e logs de chat.

O e-mail recebido contém uma string no formato `shp_<32 caracteres hexadecimais>`. Esse valor é a sua credencial.

## 3. Guarde o token com cuidado

O token autentica todas as requisições à API. Trate-o como uma credencial de produção.

Faça:

* Armazene em um gerenciador de segredos (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Doppler ou similar).
* Em scripts locais, exporte como variável de ambiente em vez de hardcoded.

Não faça:

* Não commit em repositórios, mesmo privados.
* Não compartilhe em chats, prints, vídeos ou tickets.
* Não inclua em logs de aplicação. Configure redaction para qualquer string que comece com `shp_`.

Se houver suspeita de vazamento, rotacione o token. Assinantes Sheep Plus, Sheep Pro e Sheep Pro Max podem usar o link do e-mail original; usuários Black Sheep executam `/token` novamente no Discord. O token anterior fica inválido no instante da rotação.

## 4. Faça sua primeira chamada

Use seu terminal. Substitua `shp_API_KEY_AQUI` pelo valor recebido por e-mail.

```bash
curl -X POST "https://sheep.byfranke.com/api/ai/ask" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"question": "O que é o framework MITRE ATT&CK?"}'
```

A resposta sai em JSON. O campo `response` traz o texto gerado.

```json
{
  "success": true,
  "response": "MITRE ATT&CK é um framework público que cataloga táticas...",
  "model": "sheep",
  "served_by": "scout",
  "tokens_used": 312,
  "usage": {
    "prompt_tokens": 84,
    "completion_tokens": 228,
    "total_tokens": 312,
    "estimated": false
  },
  "timestamp": "2026-05-13T18:42:11Z"
}
```

## 5. Confira seu plano e saldo

Antes de despachar volume, verifique sua conta.

```bash
curl -X GET "https://sheep.byfranke.com/api/profile" \
  -H "X-Sheep-Token: shp_API_KEY_AQUI"
```

A resposta traz o plano vigente, modelos liberados e tokens consumidos e restantes no período corrente. Esse endpoint não consome quota.

## Próximos passos

Para entender a estrutura completa da API, consulte `sheep-api/README.md`.

Para escolher um modelo específico, leia `sheep-api/models.md`.

Se você já tem um cliente escrito para o protocolo Anthropic Messages API (SDK oficial `@anthropic-ai/sdk` ou `anthropic`, agentes como OpenClaude, Cline, Cursor, Aider), use o caminho compatível em `sheep-api/anthropic-compatibility.md`. Você não precisa reescrever a integração; basta apontar a base URL para `https://sheep.byfranke.com` e usar seu token Sheep.

Para integrar com n8n, leia `sheep-api/integrations/n8n.md`.

Para usar via CLI oficial em vez de curl, veja `sheep-cli/README.md`.

Para entender o que o Sheep Bot oferece dentro do Discord, veja `sheep-bot/README.md`.
