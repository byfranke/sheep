# Autenticação

A Sheep API usa um único header para autenticar requisições.

## O header

Todas as requisições autenticadas devem incluir:

```
X-Sheep-Token: shp_API_KEY_AQUI
```

O valor é literal. Não use prefixos como `Bearer` ou `Token`. O header `Authorization` não é aceito.

O formato do token é fixo. Ele começa com `shp_` seguido por 32 caracteres hexadecimais. Qualquer valor fora desse formato é rejeitado antes de qualquer outra validação.

## Validação

A API valida o token em cada requisição.

Formato inválido retorna `401 Unauthorized` com código `invalid_token_format`. A causa típica é colagem incompleta, espaço extra ou prefixo errado.

Token desconhecido retorna `401 Unauthorized` com código `token_not_found`. O mesmo código cobre tokens que nunca existiram e tokens que foram rotacionados. A API não distingue os dois casos por design.

Assinatura sem direito retorna `402 Payment Required`. Os códigos possíveis e a ação correspondente estão em `errors.md`.

## Emitir o token

Há dois caminhos de emissão, conforme o tipo da assinatura.

* **Sheep Plus, Sheep Pro e Sheep Pro Max.** O primeiro e-mail enviado pela Sheep Store após a confirmação da assinatura traz um link de geração de token. Clique no link para emitir a primeira chave sem precisar entrar no Discord.
* **Black Sheep e Black Sheep Trial.** Execute `/token` no servidor da comunidade Sheep no Discord. O bot valida a conta e dispara a entrega do token.

Consulte `getting-started.md` na raiz deste manual para o passo a passo detalhado.

Pontos importantes em ambos os caminhos:

* O token é entregue exclusivamente por e-mail. O valor nunca é exibido em nenhuma interface visual.
* O e-mail vinculado é fixo após a primeira emissão. Alterações exigem contato com o suporte.
* Emissões posteriores rotacionam o token vigente.

## Rotacionar o token

Para rotacionar, repita o caminho usado na emissão original. Assinantes pagos clicam no link de geração de token no e-mail vigente; usuários Black Sheep executam `/token` novamente no Discord. O token anterior é invalidado no mesmo instante.

O saldo de tokens consumidos no período corrente é preservado. Rotação não reseta quota.

Há um limite de uma rotação bem-sucedida por janela de cinco minutos por conta. Falhas de validação não consomem essa janela.

## Revogar o token

Não existe operação explícita para deixar a conta sem token. Para revogar de fato, rotacione e descarte o novo valor sem usar.

Tokens cujo plano expirou recebem `402 Payment Required` em todas as chamadas. Renovar o plano restaura o acesso sem precisar reemitir o token.

## Verificar saúde do token

Use `GET /api/profile` para verificar autenticação sem consumir quota. O endpoint autentica, retorna o plano e os contadores atuais e não dispara nenhuma chamada de IA.

Consulte `endpoints/profile.md` para o formato completo da resposta.

## Boas práticas

Trate o token como credencial de produção. Não inclua em controle de versão. Não exponha em logs. Implemente redaction automática para qualquer string que comece com `shp_`.

Consulte `best-practices.md` para a lista completa de recomendações operacionais.
