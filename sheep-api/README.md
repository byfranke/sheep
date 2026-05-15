# Sheep API

A Sheep API é a interface HTTP do ecossistema Sheep. Ela expõe consultas de IA, análise de Indicadores de Comprometimento (IOCs) e leitura de feeds curados de Threat Intelligence para integração programática.

## Para quem é

A Sheep API atende três tipos de uso:

* Pipelines de SOC que precisam enriquecer e narrar alertas antes da triagem humana.
* Plataformas SOAR e workflows automatizados que consultam reputação multi-fonte e mapeiam observáveis para o framework MITRE ATT&CK.
* Aplicações internas e ferramentas de linha de comando que dão acesso conversacional à IA do Sheep para analistas.

A API não oferece operações administrativas, gestão de assinaturas ou backoffice. Esses fluxos pertencem ao bot do Discord e à Sheep Store.

## Base

Endpoint base: `https://sheep.byfranke.com`

Todas as requisições devem usar HTTPS. Não há endpoint HTTP em texto puro.

## Como ler este manual

Comece pelos conceitos. Eles definem o vocabulário usado em todos os endpoints.

* `authentication.md` apresenta o header de autenticação e o ciclo de vida do token.
* `plans-and-quota.md` explica como o consumo é medido em tokens Sheep e como cada plano define seu teto mensal.
* `models.md` descreve os tiers de modelo disponíveis e quando usar cada um.
* `rate-limits.md` define os limites de taxa por endpoint.
* `errors.md` documenta o contrato de erro e a lista de códigos.
* `best-practices.md` consolida recomendações operacionais para produção.

Depois, consulte o endpoint que você precisa.

* `endpoints/ask.md` para conversação livre com a IA.
* `endpoints/analyze.md` para análise estruturada de um IOC isolado.
* `endpoints/profile.md` para verificar plano, saldo e modelos liberados.
* `endpoints/status.md` para health check público.
* `endpoints/models.md` para descobrir os modelos disponíveis.
* `endpoints/feeds.md` para consumir feeds de Threat Intelligence.

Quando precisar de código pronto, vá para os exemplos.

* `examples/curl.md`, `examples/python.md`, `examples/nodejs.md` e `examples/powershell.md`.
* `integrations/n8n.md` traz workflows prontos para automação.

## Princípios de contrato

Estes princípios se aplicam a todos os endpoints. Eles definem o que muda e o que permanece estável.

Estabilidade de campos. Nomes de campos em respostas são estáveis. Novos campos podem aparecer; campos existentes não são removidos sem aviso prévio.

Códigos de erro como contrato. Clientes devem ramificar comportamento por `error.code`, não por mensagens humanas. Mensagens podem mudar entre versões; códigos só mudam com aviso prévio.

Aviso prévio. Mudanças que afetam código cliente recebem aviso de pelo menos trinta dias na comunidade do Discord e no `CHANGELOG.md` deste manual.

Manutenção sem janela fixa. Atualizações são aplicadas sem interrupção observável. Não há janela de manutenção pré-anunciada.
