# Sheep Analyze

`/analyze` é o comando de análise estruturada de Indicadores de Comprometimento do Sheep Bot. Envia um IOC, CVE ou família de malware e recebe um verdito categórico, score de risco, tags, recomendações e mapeamento MITRE ATT&CK quando aplicável.

Use `/analyze` quando o alvo é objetivo e você precisa de saída previsível para triagem rápida. Para conversação livre ou perguntas em texto natural, prefira `/ask`.

## Quem pode usar

Acesso público. Funciona em qualquer servidor onde o Sheep Bot está instalado.

Membros free têm limite de 10 execuções por mês. O contador zera no primeiro dia de cada mês UTC.

Membros Black Sheep, Pro, Pro Max e Enterprise não têm limite mensal de execuções no Discord. O `/analyze` no Discord não consome tokens da quota da Sheep API do plano, independentemente do vínculo via `/activate`.

`/analyze` concede 10 pontos de XP por execução bem-sucedida no sistema de ranking. Detalhes em `../ranking.md`.

## Argumentos

O bot apresenta o slash command no Discord com um único campo:

* `ioc`. Valor do alvo. Aceita IP, domínio, URL, hash MD5/SHA-1/SHA-256.

O bot detecta o tipo automaticamente a partir do valor enviado. Não há campo de tipo no Discord. Quando o valor é ambíguo, o bot escolhe a interpretação mais provável e indica o tipo detectado na resposta.

A escolha do tier de IA é feita automaticamente. Não há campo de modelo no Discord. Para escolher tipo e modelo explicitamente, use o endpoint `POST /api/ai/analyze` na Sheep API ou as ferramentas de linha de comando do Sheep CLI.

## Tipos detectados

O detector reconhece automaticamente:

* Endereços IPv4 e IPv6.
* Nomes de domínio.
* Hashes MD5, SHA-1 e SHA-256.
* URLs completas.

CVE, nome de família de malware e tipos complementares estão disponíveis ao chamar a Sheep API diretamente.

## Exemplos de uso

Análise de IP:

```
/analyze ioc:8.8.8.8
```

Análise de domínio:

```
/analyze ioc:malicious.example.com
```

Análise de hash:

```
/analyze ioc:44d88612fea8a8f36de82e1278abb02f
```

Análise de URL:

```
/analyze ioc:https://malicious.example.com/payload
```

No Discord, o slash command abre o campo de entrada `ioc` automaticamente. Cole o valor e envie. O tipo é resolvido pelo bot.

## O que esperar na resposta

O bot publica um embed estruturado com os campos abaixo.

* Veredito. Um de `benign`, `suspicious`, `malicious`, `inconclusive`.
* Confiança. Pontuação de 0 a 100. Vereditos `inconclusive` saem sempre com confiança baixa.
* Sumário. Uma ou duas frases factuais, adequadas para colar em ticket.
* Score de risco. Valor numérico de 0 a 100, derivado das fontes consultadas.
* Tags. Etiquetas agregadas das fontes (família de malware, ASN, geolocalização, categorias de serviço).
* Principais observações. Lista curta com as três a sete descobertas mais acionáveis.
* IOCs secundários. IOCs adicionais que o sistema extraiu do contexto (por exemplo, C2 domains correlatos a um IP).
* Técnicas MITRE ATT&CK. IDs de técnicas e táticas citadas quando aplicável.
* Recomendações. Recomendações operacionais defensivas.
* Referências. URLs citadas pela análise quando aplicável.

O uso do `/analyze` no Discord não debita tokens da quota da Sheep API. O contador relevante é o limite mensal de execuções por usuário, verificável em `/membership`. A quota de tokens do plano é consumida apenas em chamadas diretas à Sheep API e nas integrações que usam token pago (Sheep CLI e Sheep Web).

## Quando o veredito é `inconclusive`

O veredito `inconclusive` aparece quando as fontes consultadas não retornam dados suficientes para uma classificação confiável. Causas comuns:

* IOC muito recente, ainda não indexado por fontes de reputação.
* IOC sem histórico público (por exemplo, IPs internos).
* Fontes upstream temporariamente indisponíveis.

Ação recomendada: aguardar algumas horas e repetir, ou pedir uma análise narrativa via `/ask` com contexto adicional sobre o que foi observado.

## IOCs internos sensíveis

Para IOCs internos que não devem ser submetidos a fontes externas de reputação, use a Sheep API diretamente com `POST /api/ai/analyze` e o parâmetro `enrich: false`. O caminho via `/analyze` no Discord sempre consulta as fontes externas configuradas.

Veja `../../sheep-api/endpoints/analyze.md` para detalhes do uso via API.

## Limites e tratamento de erros

`ioc` vazio. O bot rejeita antes de consumir cota.

Valor de `ioc` que não bate com nenhum tipo conhecido (IP, domínio, hash, URL). O bot retorna mensagem clara orientando ajuste do valor. Não consome cota.

Quota mensal esgotada (free). Bot orienta upgrade ou aguardar virada do mês.

Em planos pagos não há esgotamento de saldo aplicável ao `/analyze` no Discord, pois o comando não consome tokens da Sheep API. Em chamadas diretas à Sheep API com token pago, a resposta indica saldo insuficiente quando aplicável.

Falha transitória nas fontes upstream. O bot tenta concluir a análise com as fontes que responderam e marca as ausências na resposta. Cenário raro de falha de todas as fontes resulta em mensagem orientando retry.

## Quando usar `/ask` em vez de `/analyze`

Use `/ask` quando a pergunta envolve narrativa, contexto ou múltiplos IOCs em texto livre. O `/ask` enriquece automaticamente o prompt com reputação de IOCs detectados no texto.

Use `/analyze` quando o alvo é único, estruturado e você quer saída padronizada para automação ou triagem rápida.
