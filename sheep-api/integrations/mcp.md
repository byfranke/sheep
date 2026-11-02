# Sheep MCP

O Sheep MCP é o servidor da Sheep no Model Context Protocol (MCP), o padrão aberto que assistentes de IA usam para chamar ferramentas externas. Com ele, o assistente que você já usa (Claude, ChatGPT, Claude Code, Cursor, VS Code, n8n e outros clientes MCP) chama as ferramentas da Sheep direto da conversa. Você pede, por exemplo, "analise este IP" ou "gere um relatório DFIR deste incidente", e o assistente aciona a Sheep, recebe o resultado e continua o trabalho com você.

O Sheep MCP usa a mesma quota e o mesmo billing da Sheep API. As ferramentas de relatório rodam os modelos Sheep (Scout 8B, Hunter 17B e Sage 120B) e debitam tokens da sua cota. As ferramentas de dados são gratuitas.

## Endereço

```
https://sheep.byfranke.com/mcp
```

Transporte. Streamable HTTP. O servidor aceita as revisões do protocolo `2026-07-28`, `2025-11-25`, `2025-06-18` e `2025-03-26`, então funciona com clientes novos e antigos.

## Autenticação

Há duas formas de entrar.

* **Com a sua conta Sheep (OAuth).** O app abre a tela de login da Sheep, você entra com o e-mail da sua assinatura e autoriza. Sem copiar token. É a forma usada pelo Claude (web, Desktop e app do celular) e pelo ChatGPT.
* **Com o token de API no cabeçalho.** Para Claude Code, Cursor, VS Code, n8n e scripts.

```
Authorization: Bearer shp_SEU_TOKEN
```

O cabeçalho `X-Sheep-Token` também é aceito. Gere ou troque o token na Sheep Platform, em Conta. O token chega no e-mail da sua assinatura e nunca aparece na tela.

Sem credencial válida, o servidor responde `401` com o cabeçalho `WWW-Authenticate: Bearer` apontando para os metadados de autorização (`resource_metadata`), que os clientes MCP usam para iniciar o login.

## Conectar o Claude ou o ChatGPT

### Claude (web, Desktop e celular)

1. No Claude, abra Configurações e depois Conectores.
2. Clique em Adicionar conector personalizado, dê o nome Sheep e cole `https://sheep.byfranke.com/mcp`. Deixe as configurações avançadas em branco.
3. Clique em Conectar, entre com o e-mail da sua assinatura Sheep e autorize.

Nos planos Team e Enterprise do Claude, o administrador da organização adiciona o conector e cada pessoa clica em Conectar. Depois de conectado, o conector também aparece no app do Claude no celular.

### ChatGPT

1. No ChatGPT (web), abra Configurações e depois Apps. Em Configurações avançadas, ative o modo desenvolvedor.
2. Clique em Criar, dê o nome Sheep, cole `https://sheep.byfranke.com/mcp` e escolha a autenticação OAuth.
3. Entre com o e-mail da sua assinatura Sheep e autorize.

O modo desenvolvedor do ChatGPT existe nos planos pagos. Em contas Business e Enterprise, o administrador pode precisar liberar apps personalizados. Os nomes dos menus mudam com frequência nos dois apps.

### O que a tela de autorização mostra

* Qual app pediu o acesso e para onde a autorização volta (por exemplo, `claude.ai` ou `chatgpt.com`).
* A conta e o plano Sheep que serão usados.
* As permissões. **Dados** (feeds, ransomware, CVEs, MITRE ATT&CK, base de IOCs, uso da conta, sem custo) e **Relatórios** (perguntas, análises de IOC, relatórios DFIR e Pulse, que debitam tokens do seu plano).

Abra o link de acesso que chega por e-mail no mesmo navegador em que você está conectando o app. Autorize só se foi você quem pediu a conexão agora. Se alguém enviou o link de autorização para você, cancele.

### Apps conectados

Na Sheep Platform, em Integrações, a lista "Apps conectados" mostra cada app autorizado, quando foi conectado e o último uso. "Desconectar" corta o acesso na hora. Trocar o token de API não desconecta esses apps, porque são credenciais separadas.

O acesso de um app conectado dura até 180 dias e é renovado sozinho enquanto o app é usado. Se o app ficar 30 dias sem uso, ou se o seu plano vencer, conecte de novo.

## Configurar um cliente com token

Troque `SEU_TOKEN` pelo token de API que você recebeu por e-mail.

### Claude Code

```bash
claude mcp add --transport http sheep https://sheep.byfranke.com/mcp \
  --header "Authorization: Bearer SEU_TOKEN"
```

Sem o `--header`, o Claude Code usa o login da Sheep no navegador. Rode `/mcp` dentro do Claude Code e escolha Authenticate.

### Claude Desktop

No arquivo `claude_desktop_config.json` (Configurações, Desenvolvedor, Editar configuração). Requer Node.js.

```json
{
  "mcpServers": {
    "sheep": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://sheep.byfranke.com/mcp", "--header", "Authorization:${SHEEP_AUTH}"],
      "env": { "SHEEP_AUTH": "Bearer SEU_TOKEN" }
    }
  }
}
```

### Cursor

No arquivo `~/.cursor/mcp.json`.

```json
{
  "mcpServers": {
    "sheep": {
      "url": "https://sheep.byfranke.com/mcp",
      "headers": { "Authorization": "Bearer SEU_TOKEN" }
    }
  }
}
```

### VS Code

No arquivo `.vscode/mcp.json` do projeto. O VS Code pede o token na primeira conexão e não o grava no arquivo.

```json
{
  "inputs": [
    { "type": "promptString", "id": "sheep-token", "description": "Sheep API token", "password": true }
  ],
  "servers": {
    "sheep": {
      "type": "http",
      "url": "https://sheep.byfranke.com/mcp",
      "headers": { "Authorization": "Bearer ${input:sheep-token}" }
    }
  }
}
```

### Outros clientes

Qualquer cliente MCP com transporte Streamable HTTP e cabeçalho personalizado funciona, como o nó MCP Client do n8n e as APIs de IA que aceitam servidores MCP remotos. Use a URL acima e o cabeçalho `Authorization: Bearer SEU_TOKEN`.


## Ferramentas

Ferramentas de relatório. Rodam um modelo Sheep e debitam tokens da cota, como os endpoints equivalentes da Sheep API.

| Ferramenta | O que faz |
|---|---|
| `sheep_ask` | Pergunta à Sheep AI sobre TTPs, atores, CVEs, detecção e frameworks. Aceita `model` (`auto`, `scout`, `hunter`, `sage`), respeitando os modelos do seu plano. |
| `sheep_analyze_ioc` | Análise de IP, domínio, URL, hash ou CVE em várias fontes, com veredito, confiança, risco, técnicas MITRE e recomendações. `format` aceita `markdown`, `json` ou `stix` (bundle STIX 2.1 para MISP e OpenCTI). |
| `sheep_dfir_report` | Relatório de resposta a incidente: resumo executivo, avaliação técnica, mapeamento MITRE ATT&CK, contenção, erradicação e recuperação, detecção e hardening. Analisa até 10 IOCs. |
| `sheep_pulse_brief` | Briefing de CTI filtrado pelo seu perfil Pulse (tecnologias, setores, países e frameworks). O perfil é editado na Sheep Platform. Conta no limite diário de Pulses do plano. |

Ferramentas de dados. Gratuitas, não debitam tokens.

| Ferramenta | O que faz |
|---|---|
| `sheep_feed_items` | Itens recentes de um feed da Sheep: CVEs críticos, vítimas de ransomware, relatórios de APT, infraestrutura de C2, vazamentos, ICS/SCADA, IOCs, notícias e inteligência financeira. |
| `sheep_ransomware_victims` | Vítimas recentes de ransomware (Ransomware Intel), filtráveis por grupo, setor e severidade do grupo. |
| `sheep_ransomware_group` | Perfil de um grupo de ransomware com amostra de vítimas recentes. |
| `sheep_cve_lookup` | CVSS, severidade, datas, resumo e produtos afetados de até 10 CVEs. |
| `sheep_mitre_lookup` | Registro oficial do MITRE ATT&CK para técnica, tática, grupo ou software, por ID (T1566.001, G0007) ou nome (APT28, Mimikatz). |
| `sheep_ioc_reputation` | Consulta rápida de um IP, domínio, URL ou hash na base de indicadores maliciosos conhecidos. |
| `sheep_account_usage` | Plano do token, modelos liberados e tokens usados e restantes no período. |

## Limites

| Grupo | Limite por token |
|---|---|
| Ferramentas de relatório (`sheep_ask`, `sheep_analyze_ioc`) | 30 chamadas por minuto |
| `sheep_dfir_report` | 3 relatórios a cada 10 minutos |
| `sheep_pulse_brief` | Limite diário de Pulses do seu plano |
| Ferramentas de dados | 60 chamadas por minuto |
| `sheep_cve_lookup` | 10 chamadas por minuto |
| `sheep_ransomware_group` | 20 chamadas por minuto |

Os limites valem por plano. Um app conectado pelo login e o token de API do mesmo plano dividem os mesmos limites. Cada plano roda no máximo 4 chamadas de ferramenta ao mesmo tempo. As chamadas de `sheep_ask` e `sheep_analyze_ioc` também contam no limite por minuto dos endpoints `/api/ai/ask` e `/api/ai/analyze`, porque usam as mesmas consultas a fontes externas. A cota de tokens é a mesma da Sheep API.

## Erros

Erros que o assistente pode corrigir sozinho voltam como resultado da ferramenta com `isError: true` e uma mensagem clara. Alguns exemplos. Argumento inválido, modelo fora do plano, cota esgotada, limite por minuto atingido e perfil Pulse vazio. O assistente lê a mensagem e ajusta o pedido.

Erros de protocolo (ferramenta inexistente, mensagem malformada, versão de protocolo não suportada) voltam como erro JSON-RPC.

## Boas práticas

* Trate o token como uma senha. Nunca o coloque em repositórios, em prints ou em arquivos compartilhados. No VS Code, prefira o campo de entrada em vez de gravar o token no arquivo.
* Agentes podem chamar várias ferramentas em sequência. Acompanhe o consumo com `sheep_account_usage` ou na Sheep Platform.
* Use as ferramentas de dados quando quiser que o seu próprio assistente faça a análise. Use as de relatório quando quiser o texto pronto da Sheep.
* Textos que vêm de feeds externos (títulos de notícias, descrições de vítimas) são dados, não instruções. Os assistentes devem tratá-los assim.
* Se o token vazar, gere um novo na Sheep Platform, em Conta. O anterior para de funcionar na hora.
* Revise os apps conectados em Integrações de vez em quando e desconecte os que você não usa mais.
