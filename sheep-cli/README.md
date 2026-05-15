# Sheep CLIs

A linha Sheep CLI oferece ferramentas de linha de comando oficiais para uso em terminais, scripts shell e pipelines locais. Cada CLI tem foco específico e pode ser instalada de forma independente.

As CLIs consomem a Sheep API com o mesmo token usado em integrações via curl ou HTTP. Para emitir um token, consulte `../getting-started.md`.

## Ferramentas disponíveis

### sheep-cli

REPL interativo que conversa com a Sheep API com histórico, contexto persistente e atalhos para alternar modelo. Use no dia a dia em terminal.

Repositório público: `https://github.com/byfranke/sheep-cli`.

### sheep-ask-cli

Ferramenta de linha única para fazer uma pergunta e receber a resposta. Use em scripts shell, atalhos e automações locais.

Repositório público: `https://github.com/byfranke/sheep-ask-cli`.

### sheep-analyze-cli

Ferramenta especializada em análise de IOC. Lê um valor (IP, domínio, hash, URL, CVE) e retorna a análise estruturada do endpoint `/api/ai/analyze`.

Repositório público: `https://github.com/byfranke/sheep-analyze-cli`.

### sheep-feeds-cli

Ferramenta de leitura dos feeds de Threat Intelligence. Suporta filtros, paginação e formatos de saída adequados a pipelines (JSON, texto plano, tabela).

Repositório público: `https://github.com/byfranke/sheep-feeds-cli`.

## Instalação

Cada CLI tem instruções próprias no README do repositório correspondente. O padrão geral é uma das opções abaixo, conforme a ferramenta:

* Pacote npm para CLIs escritas em Node.js.
* Pacote pip para CLIs escritas em Python.
* Binário pré-compilado disponível em GitHub Releases.
* Script `install.sh` no próprio repositório.

Confira o README de cada projeto para o procedimento exato.

## Configuração de token

Todas as CLIs aceitam o token Sheep por uma das formas abaixo, em ordem de precedência:

1. Argumento de linha de comando dedicado (`--token`, `-t` ou similar).
2. Variável de ambiente `SHEEP_API_TOKEN`.
3. Arquivo de configuração próprio da CLI (cada projeto define a localização).

A forma recomendada para uso interativo é a variável de ambiente. Para uso em scripts, configure a variável no início do script ou injete via gerenciador de segredos.

```bash
export SHEEP_API_TOKEN="shp_API_KEY_AQUI"
```

Não passe o token literalmente em comandos. Histórico de shell, prints e logs de processo podem capturar o valor.

## Suporte

Issues técnicas: abra no repositório GitHub correspondente.

Dúvidas gerais: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
