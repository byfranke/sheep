# Manual do Usuario - Sheep 4

## Sumário

1.  **[Introdução](#1-introducao)**
    * 1.1 Visão Geral do Sistema
    * 1.2 Arquitetura e Recursos
2.  **[Sheep AI](#2-sheep-ai)**
    * 2.1 Pergunte Qualquer Coisa (/ask)
    * 2.2 Resposta a Incidentes (/incident_response)
3.  **[Workflows Profissionais](#3-workflows-profissionais)**
    * 3.1 Automação de Workflows (/workflow)
4.  **[Ferramentas de Segurança](#4-ferramentas-de-seguranca)**
    * 4.1 Análise Multi-Fonte (/analyze)
    * 4.2 Reputação de IP (/ipcheck)
    * 4.3 Relatório de Abuso de IP (/ipreport)
    * 4.4 Integração com VirusTotal (/virustotal)
5.  **[Ferramentas de Reconhecimento](#5-ferramentas-de-reconhecimento)**
    * 5.1 Inteligência de Host (/shodan)
    * 5.2 Varredura de Portas (/portscan)
    * 5.3 Análise de URL (/urlscan)
6.  **[Monitoramento e Feeds de Inteligência](#6-monitoramento-e-feeds-de-inteligencia)**
    * 6.1 Notícias de Cibersegurança RSS (/rssfeed)
    * 6.2 Feeds de IOC (/iocfeed)
7.  **[Sistema de Membros](#7-sistema-de-membros)**
    * 7.1 Limites do Plano Gratuito
    * 7.2 Membros Black Sheep
    * 7.3 Trial Gratuito (/trial)
    * 7.4 Resgate de Código (/redeem)
    * 7.5 Status da Membresia (/membership)
8.  **[Administração do Servidor](#8-administracao-do-servidor)**
    * 8.1 Comandos de Moderação
    * 8.2 Sistema de Boas-Vindas (/welcome)
    * 8.3 Configuração de Auto-Role (/autorole)
9.  **[Comandos Utilitários](#9-comandos-utilitarios)**
    * 9.1 Ajuda (/help)
    * 9.2 Sobre (/about)
    * 9.3 Versão (/version)
    * 9.4 Idioma (/language)
10. **[Acesso à API](#10-acesso-a-api)**
    * 10.1 Gerenciamento de Token (/token)
11. **[Políticas de Uso](#11-politicas-de-uso)**

---

## 1. Introducao

### 1.1 Visao Geral do Sistema

Sheep 4 e um assistente avancado de ciberseguranca para Discord, projetado para inteligencia de ameacas, analise de seguranca e automacao de operacoes CTI. Desenvolvido para profissionais de seguranca, analistas de SOC e threat hunters, o sistema centraliza consultas a multiplas APIs de seguranca em uma interface unificada.

**Acesso Oficial:** [Sheep](https://sheep.byfranke.com/)

**Termos de Servico:** [Termos de Servico Oficiais](https://sheep.byfranke.com/pages/terms.html)

### 1.2 Arquitetura e Recursos

Sheep 4 opera com um modelo hibrido avancado:

* **Integracao com IA:** Sheep AI - motor de inteligencia artificial proprietario para analise contextual.
* **Machine Learning:** Sistema de fallback automatico com reconhecimento de padroes e capacidades de aprendizado.
* **Integracao Multi-API:** Acesso unificado a VirusTotal, AbuseIPDB, Shodan, URLScan.io e AlienVault OTX.
* **Monitoramento em Tempo Real:** Agregacao continua de feeds de inteligencia de ameacas.

---

## 2. Sheep AI

Comandos que utilizam inteligência artificial (Sheep AI) para análise contextual e resposta a incidentes.

### 2.1 Pergunte Qualquer Coisa (/ask)

Integração com Sheep AI para consultas em linguagem natural, conselhos de cibersegurança e suporte à resposta a incidentes.

**Recursos:**

* Perguntas gerais de cibersegurança
* Consultas de inteligência de ameaças
* Orientação para resposta a incidentes
* Melhores práticas de segurança
* Análise de vulnerabilidades
* Investigação de malware

**Sintaxe:**

```
/ask <pergunta>
```

**Exemplos:**

* `/ask O que é um ataque de SQL injection?`
* `/ask Analise este hash 13400d5c844b7ab9aacc81822b1e7f02`
* `/ask Explique o framework MITRE ATT&CK`

### 2.2 Resposta a Incidentes (/incident_response)

Integração com Sheep AI para resposta guiada a incidentes, incluindo instruções passo a passo e melhores práticas.

**Recursos:**

* Resposta guiada a incidentes
* Instruções passo a passo
* Recomendações de playbooks
* Orientação para contenção de ameaças
* Coleta de evidências forenses

**Recursos Principais:**

* **Planos Gerados por IA:** Usa Sheep AI para gerar planos de resposta contextuais e profissionais.
* **Suporte Bilíngue:** Responde automaticamente no seu idioma preferido (Inglês ou Português).
* **ID Único de Incidente:** Cada resposta inclui um ID de incidente rastreável (ex: `IR-20251205-A1B2C3D4`).
* **Referência Rápida:** Inclui ferramentas, frameworks e recursos relevantes para cada tipo de incidente.

**Tipos de Incidente:**

| Tipo | Descrição | Áreas de Foco |
|------|-----------|---------------|
| `malware` | Infecção por malware detectada | ID da família do malware, vetor de infecção, detecção C2, forense de memória |
| `breach` | Violação de dados com exfiltração | Classificação de dados, notificação regulatória (LGPD/GDPR), coordenação jurídica |
| `phishing` | Campanha de phishing direcionada | Escopo da campanha, comprometimento de credenciais, análise de URL/anexos |
| `ddos` | Negação de Serviço Distribuída | Classificação do tipo de ataque, coordenação CDN/ISP, scrubbing de tráfego |
| `insider` | Detecção de ameaça interna | Timeline de atividades do usuário, preservação de evidências, coordenação RH/Jurídico |
| `ransomware` | Ataque de ransomware | Isolamento imediato, identificação da variante, verificação de backup, orientação NÃO PAGAR |
| `apt` | Ameaça Persistente Avançada | Estimativa de tempo de permanência, mecanismos de persistência, mapeamento MITRE ATT&CK |

**Níveis de Severidade:**

| Nível | Rótulo | Prioridade de Resposta |
|-------|--------|------------------------|
| `critical` | CRÍTICO | Escalação executiva necessária. Todas as mãos na massa. Continuidade do negócio em risco. |
| `high` | ALTO | Notificação à gerência sênior. Impacto significativo no negócio esperado. |
| `medium` | MÉDIO | Procedimentos padrão de resposta a incidentes. Monitorar para escalação. |
| `low` | BAIXO | Documentar e monitorar. Investigação necessária mas sem ameaça imediata. |

**Sintaxe:**

```bash
/incident_response <tipo_incidente> <severidade>
```

**Exemplos:**

```bash
/incident_response ransomware critical
/incident_response insider high
/incident_response phishing medium
/incident_response malware low
```

**Estrutura da Resposta:**

A IA gera uma resposta estruturada com 5 seções principais:

1. **Ações Imediatas (0-15 minutos):** Passos críticos de primeira resposta em ordem de prioridade.
2. **Contenção (15-60 minutos):** Passos para conter e isolar a ameaça.
3. **Erradicação:** Como eliminar completamente a ameaça dos sistemas.
4. **Recuperação:** Passos para restaurar operações normais com segurança.
5. **Pós-Incidente:** Requisitos de documentação e recomendações de melhoria.

**Exemplo de Saída:**

```
[CRÍTICO] Plano de Resposta a Incidente
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident ID: IR-20251205-A1B2C3D4
Tipo: Ataque de Ransomware
Severidade: CRÍTICO
Gerado: 2025-12-05 14:30 UTC

[Plano de Resposta Gerado por IA]
**1. AÇÕES IMEDIATAS:**
• DESCONECTAR sistemas afetados imediatamente
• NÃO pagar resgate sem consulta jurídica
• Preservar amostras criptografadas para análise
• Alertar diretoria e jurídico
...

Referência Rápida
━━━━━━━━━━━━━━━━━
**NÃO:** Pagar resgate imediatamente
**Recursos:** No More Ransom, ID Ransomware
```

**Dicas Profissionais:**

* Use `/ask` para perguntas de acompanhamento sobre passos específicos do plano.
* Use `/analyze` para investigar quaisquer IOCs descobertos durante o incidente.
* A resposta respeita sua preferência de idioma configurada via `/language`.

---

## 3. Workflows Profissionais

Procedimentos profissionais baseados em frameworks NIST/SANS. Não utiliza IA.

### 3.1 Automação de Workflows (/workflow)

Gera templates de procedimentos padronizados baseados em frameworks da indústria (NIST/SANS) para guiar analistas em operações de segurança. Este comando é estático e não utiliza IA.

**Tipos de Workflow Disponíveis:**

* `incident_response` - Procedimentos de tratamento de incidentes
* `threat_hunting` - Detecção proativa de ameaças
* `vulnerability_assessment` - Procedimentos de avaliação de segurança
* `malware_analysis` - Etapas de investigação de malware
* `forensics` - Procedimentos de forense digital

**Sintaxe:**

```
/workflow <tipo>
```

**Exemplo:** `/workflow threat_hunting`

---

## 4. Ferramentas de Segurança

Ferramentas para análise de IOCs e reputação, integradas a múltiplas APIs de segurança.

### 4.1 Análise Multi-Fonte (/analyze)

Ferramenta abrangente de enriquecimento de IOC que cruza multiplas fontes de inteligencia simultaneamente para analise completa de ameacas.

**Capacidades:**

* Enriquecimento multi-fonte com pontuacao de risco.
* Suporte para IPs, dominios, hashes e URLs.
* Recomendacoes profissionais e proximos passos sugeridos.
* Classificacao automatica de ameacas.

**Sintaxe:**

```
/analyze <ioc>
```

**Exemplos:**

* `/analyze 192.168.1.1`
* `/analyze dominio-malicioso.com`
* `/analyze 44d88612fea8a8f36de82e1278abb02f`

### 4.2 Reputação de IP (/ipcheck)

Verifica a reputacao de endereco IP usando AbuseIPDB, retornando pontuacao de confianca de abuso, historico de relatorios e informacoes geograficas.

**Informacoes Fornecidas:**

* Pontuacao de confianca de abuso (0-100%)
* Numero de relatorios
* Localizacao geografica (Pais, ISP)
* Categorias de relatorio (Brute Force, SSH Abuse, DDoS, etc.)
* Status de whitelist

**Sintaxe:**

```
/ipcheck <ip>
```

**Exemplo:** `/ipcheck 8.8.8.8`

### 4.3 Relatório de Abuso de IP (/ipreport)

Reporte enderecos IP abusivos para o AbuseIPDB para contribuir com a comunidade global de inteligencia de ameacas.

**Categorias de Relatorio:**

* DNS Compromise
* DNS Poisoning
* Fraud Orders
* DDoS Attack
* FTP Brute-Force
* Port Scan
* Phishing
* Spam
* SSH Brute-Force
* VPN IP
* Web Spam
* Hacking
* SQL Injection
* Spoofing
* Brute-Force
* Bad Web Bot
* Exploited Host
* Web App Attack
* IoT Targeted

**Sintaxe:**

```
/ipreport <ip> <categorias> <comentario>
```

**Exemplo:** `/ipreport 192.168.1.100 ssh_brute_force,port_scan Detectadas multiplas tentativas SSH falhas`

### 4.4 Integração com VirusTotal (/virustotal)

Consulta direta ao banco de dados do VirusTotal para analise abrangente de arquivos, URLs e IPs contra mais de 70 motores antivirus.

**Tipos de Entrada Suportados:**

* Hashes de arquivo (MD5, SHA1, SHA256)
* URLs
* Enderecos IP
* Dominios

**Sintaxe:**

```
/virustotal <hash/url/ip/dominio>
```

**Exemplos:**

* `/virustotal 44d88612fea8a8f36de82e1278abb02f`
* `/virustotal https://site-suspeito.com`

---

## 5. Ferramentas de Reconhecimento

Ferramentas para reconhecimento passivo, varredura de portas e análise de URLs.

### 5.1 Inteligência de Host (/shodan)

Consulta o banco de dados Shodan para reconhecimento passivo, identificando servicos expostos, vulnerabilidades e informacoes de infraestrutura.

**Informacoes Fornecidas:**

* Portas abertas e servicos
* Deteccao de sistema operacional
* Vulnerabilidades conhecidas (CVEs)
* Detalhes de certificado SSL/TLS
* Localizacao geografica
* ISP e organizacao
* Dados historicos

**Sintaxe:**

```
/shodan <ip_ou_consulta>
```

**Exemplos:**

* `/shodan 8.8.8.8`
* `/shodan apache country:BR`

### 5.2 Varredura de Portas (/portscan)

Varredura de portas ativa em tempo real usando capacidades de varredura sob demanda do Shodan.

**Nota:** Este recurso é exclusivo para membros Black Sheep Premium.

**Sintaxe:**

```
/portscan <alvo>
```

**Exemplo:** `/portscan 192.168.1.1`

### 5.3 Análise de URL (/urlscan)

Integração com URLScan.io para análise abrangente de segurança de websites, identificando comportamentos de phishing, scripts maliciosos e conteúdo suspeito.

**A Análise Inclui:**

* Captura de tela
* Análise DOM
* Requisições de rede
* Informações de certificado
* Indicadores maliciosos
* Tecnologias detectadas

**Sintaxe:**

```
/urlscan <url>
```

**Exemplo:** `/urlscan https://exemplo.com`

---

## 6. Monitoramento e Feeds de Inteligência

### 6.1 Notícias de Cibersegurança RSS (/rssfeed)

Configura entrega automatica de noticias de ciberseguranca para um canal designado. O sistema agrega conteudo de multiplas fontes confiaveis.

**Fontes Disponiveis:**

* The Hacker News
* Bleeping Computer
* Krebs on Security
* CISA Alerts
* Dark Reading
* SecurityWeek
* Threatpost
* E fontes adicionais

**Acoes:**

* `enable` - Ativar feed no canal atual
* `disable` - Desativar feed
* `status` - Verificar configuracao atual

**Sintaxe:**

```
/rssfeed <acao>
```

**Nota:** Requer permissoes de Administrador.

### 6.2 Feeds de IOC (/iocfeed)

Configura entrega automatica de Indicadores de Comprometimento do AlienVault OTX para um canal designado.

**Categorias de IOC:**

* Malware e Botnets
* Campanhas de Phishing
* Servidores de Comando e Controle (C2)
* Indicadores de Ransomware
* Exploit Kits
* Indicadores de APT

**Acoes:**

* `enable` - Ativar feed no canal atual
* `disable` - Desativar feed
* `status` - Verificar configuracao atual

**Sintaxe:**

```
/iocfeed <acao>
```

**Nota:** Requer permissoes de Administrador.

---

## 7. Sistema de Membros

### 7.1 Limites do Plano Gratuito

Usuarios gratuitos tem limites mensais em comandos de seguranca para garantir uso justo:

| Comando | Limite Mensal |
|---------|---------------|
| /analyze | 10 usos |
| /ask | 10 usos |
| /ipcheck | 10 usos |
| /ipreport | 10 usos |
| /portscan | 10 usos |
| /shodan | 10 usos |
| /urlscan | 10 usos |
| /virustotal | 10 usos |
| /workflow | 10 usos |

Os limites sao resetados no primeiro dia de cada mes.

### 7.2 Membros Black Sheep

A membresia premium remove todos os limites de uso e fornece acesso a recursos exclusivos.

**Beneficios:**

* Uso ilimitado de todos os comandos de seguranca
* Acesso exclusivo ao /portscan
* Token de API para integracao com outros servicos byFranke
* Suporte prioritario
* Role especial no Discord da Comunidade Sheep
* Acesso a canais exclusivos de membros

**Planos Disponiveis:**

Para precos atualizados, consulte a [Loja Oficial](https://sheep.byfranke.com/pages/store.html):

| Plano | Duracao |
|-------|--------|
| Trial | 3 dias (gratis, unica vez) |
| 3 Meses | 90 dias |
| 6 Meses | 180 dias |
| 12 Meses | 365 dias |

### 7.3 Trial Gratuito (/trial)

Solicite um trial gratuito de 3 dias da membresia Black Sheep para experimentar os recursos premium.

**Limitacoes:**

* Um trial por conta Discord
* Um trial por endereco de email
* Codigo de trial valido por 30 dias apos geracao

**Sintaxe:**

```
/trial <email>
```

**Exemplo:** `/trial usuario@exemplo.com`

O codigo de trial sera enviado para o endereco de email fornecido.

### 7.4 Resgate de Código (/redeem)

Ative uma membresia Black Sheep usando um codigo de resgate.

**Formato do Codigo:** `SB3M-XXXX-XXXX-XXXX` ou `SB6M-XXXX-XXXX-XXXX` ou `SB12-XXXX-XXXX-XXXX`

**Sintaxe:**

```
/redeem <codigo>
```

**Exemplo:** `/redeem SB3M-A1B2-C3D4-E5F6`

### 7.5 Status da Membresia (/membership)

Verifique seu status atual de membresia, incluindo detalhes do plano, data de expiracao e estatisticas de uso.

**Sintaxe:**

```
/membership
```

---

## 8. Administração do Servidor

### 8.1 Comandos de Moderação

Comandos padrao de moderacao para gerenciamento de servidor. Requer permissoes apropriadas.

**Banir Usuario:**

```
/ban <usuario> [motivo]
```

**Expulsar Usuario:**

```
/kick <usuario> [motivo]
```

**Timeout de Usuario:**

```
/mute <usuario> [duracao] [motivo]
```

**Remover Timeout:**

```
/unmute <usuario>
```

### 8.2 Sistema de Boas-Vindas (/welcome)

Configure mensagens automaticas de boas-vindas para novos membros do servidor.

**Acoes:**

* `enable` - Ativar mensagens de boas-vindas no canal atual
* `disable` - Desativar mensagens de boas-vindas
* `status` - Verificar configuracao atual

**Sintaxe:**

```
/welcome <acao>
```

**Nota:** Requer permissoes de Administrador.

### 8.3 Configuração de Auto-Role (/autorole)

Configure atribuicao automatica de role para novos membros.

**Acoes:**

* `set` - Definir uma role para ser atribuida automaticamente
* `remove` - Remover configuracao de auto-role
* `status` - Verificar configuracao atual

**Sintaxe:**

```
/autorole <acao> [role]
```

**Nota:** Requer permissoes de Administrador.

---

## 9. Comandos Utilitários

### 9.1 Ajuda (/help)

Exibe comandos disponiveis baseados no seu nivel de permissao e status de membresia.

**Sintaxe:**

```
/help
```

### 9.2 Sobre (/about)

Exibe informacoes sobre o Sheep 4, incluindo versao, recursos e informacoes do desenvolvedor.

**Sintaxe:**

```
/about
```

### 9.3 Versão (/version)

Exibe versao atual do bot e informacoes recentes do changelog.

**Sintaxe:**

```
/version
```

### 9.4 Idioma (/language)

Altere seu idioma preferido para respostas do bot.

**Idiomas Suportados:**

* Ingles (en)
* Portugues (pt)
* Espanhol (es)

**Sintaxe:**

```
/language <codigo>
```

**Exemplo:** `/language pt`

---

## 10. Acesso à API

### 10.1 Gerenciamento de Token (/token)

Gerencie seu token pessoal de API para acesso programatico aos recursos do Sheep 4.

**Acoes:**

* `generate` - Gerar um novo token de API
* `revoke` - Revogar token atual
* `status` - Verificar status do token

**Sintaxe:**

```
/token <acao>
```

**Nota:** Requer membresia Black Sheep para acesso a API.

---

## 11. Políticas de Uso

### Uso Aceitavel

* Todas as varreduras e analises devem ser realizadas apenas em alvos autorizados.
* Nao use o bot para atividades ilegais ou tentativas de acesso nao autorizado.
* Respeite os limites de uso e nao tente contornar restricoes de uso. **Violacoes estao sujeitas a banimento permanente.**
* Reporte quaisquer bugs ou vulnerabilidades atraves dos canais oficiais.

### Privacidade de Dados

* Sheep 4 nao coleta mensagens privadas ou conteudo fora de comandos explicitamente emitidos.
* Apenas dados essenciais (IDs de usuario, comandos executados, parametros de comando) sao coletados para auditoria, monitoramento de seguranca e limitacao de uso.
* Usuarios podem solicitar exclusao de seus dados pessoais atraves dos canais oficiais de suporte.
* Todos os dados coletados sao gerenciados em conformidade com LGPD, GDPR e regulamentacoes equivalentes de protecao de dados.

### Aviso Legal

O desenvolvedor nao e responsavel pelo uso indevido de ferramentas de varredura e analise. Os usuarios sao os unicos responsaveis por garantir que possuem autorizacao adequada antes de realizar quaisquer avaliacoes de seguranca.

Para termos completos, consulte os [Termos de Servico Oficiais](https://sheep.byfranke.com/pages/terms.html).

---

## Suporte e Contato

Para perguntas, sugestoes, relatorios de problemas ou consultas legais:

* **Comunidade Discord:** [Sheep Community](https://discord.gg/n8cpR9hJ2y)
* **Formulario de Suporte:** [Contato Oficial](https://byfranke.com/index-eng.html#Contact)

---

**Versao do Documento:** 4.0.0

**Ultima Atualizacao:** Dezembro 2025
