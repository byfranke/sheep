# Manual do Usuário - Sheep v3.7.1

## Sumário

1.  **[Introdução](#1-introdução)**
    * 1.1 Visão Geral do Sistema
    * 1.2 Arquitetura Híbrida (v3.7.1)
2.  **[Assistente de Inteligência Artificial (/ask)](#2-assistente-de-inteligência-artificial-ask)**
3.  **[Cyber Threat Intelligence (CTI)](#3-cyber-threat-intelligence-cti)**
    * 3.1 Análise Avançada (`/threat_intel`)
    * 3.2 Validação de Indicadores (`/ioc_check`)
    * 3.3 Análise de URLs (`/urlscan`)
    * 3.4 Integração VirusTotal (`/virustotal`)
    * 3.5 Reputação de IP (`/ipcheck`)
4.  **[Monitoramento e Feeds de Inteligência](#4-monitoramento-e-feeds-de-inteligência)**
    * 4.1 Fontes de Dados (RSS e OTX)
    * 4.2 Configuração de Canais (`/rssfeed`, `/iocfeed`)
    * 4.3 Status do Sistema
5.  **[Reconhecimento e Scanning](#5-reconhecimento-e-scanning)**
    * 5.1 Intelligence de Hosts (`/shodan`)
    * 5.2 Port Scanning (`/portscan`)
6.  **[Operações e Workflows](#6-operações-e-workflows)**
    * 6.1 Workflows Padronizados
    * 6.2 Resposta a Incidentes
7.  **[Administração de Servidor (Staff)](#7-administração-de-servidor-staff)**
8.  **[Licenciamento (Black Sheep)](#8-licenciamento-black-sheep)**

---

## 1. Introdução

### 1.1 Visão Geral do Sistema
O **Sheep Bot** é um assistente avançado de cibersegurança para Discord, projetado para fornecer inteligência de ameaças, análises de segurança e automação de operações de CTI. Desenvolvido para profissionais de segurança, analistas SOC e *threat hunters*, o sistema centraliza a consulta a múltiplas APIs de segurança em uma única interface.

### 1.2 Arquitetura Híbrida (v3.7.1)
A build "Sheep Threat Analyst" opera em um modelo híbrido:
* **Integração de IA:** Modelos Llama 3 e Mistral para processamento contextual de perguntas e análises.
* **Machine Learning:** Fallback automático para algoritmos tradicionais de classificação.
* **Mecanismo de Feedback:** Indicadores visuais de processamento para análises complexas (timeout de 45s).

---

## 2. Assistente de Inteligência Artificial (`/ask`)

O módulo central da versão 3.7.1. O `/ask` utiliza uma *engine* de ML com aprendizado contínuo para responder perguntas técnicas e analisar ameaças com contexto.

**Funcionalidades:**
* Extração e análise automática de IoCs dentro da pergunta.
* Explicação de conceitos de segurança (APTs, TTPs, Malware families).
* Consultas contextuais (ex: "Qual a relação entre este hash e o grupo Lazarus?").

**Sintaxe:**
```text
/ask <pergunta_ou_instrução>
````

*Exemplo:* `/ask analyze this hash 13400d5c844b7ab9aacc81822b1e7f02`

-----

## 3\. Cyber Threat Intelligence (CTI)

Esta seção detalha as ferramentas de análise prioritária para enriquecimento de dados e investigação.

### 3.1 Análise Avançada (`/threat_intel`)

A ferramenta mais robusta de análise do Sheep Bot. Realiza o enriquecimento de IoCs cruzando múltiplas fontes de inteligência simultaneamente.

**Capacidades:**

  * Enriquecimento "Multi-source" com scoring de risco.
  * Suporte a IPs, Domínios, Hashes e URLs.
  * Geração de recomendações profissionais e próximos passos.

**Sintaxe:**

```text
/threat_intel <ioc>
```

*Exemplo:* `/threat_intel malicious-domain.com`

### 3.2 Validação de Indicadores (`/ioc_check`)

Ferramenta ágil para verificação rápida da reputação de um indicador. Ideal para triagem inicial antes de uma análise profunda.

**Sintaxe:**

```text
/ioc_check <ioc>
```

### 3.3 Análise de URLs (`/urlscan`)

Integração com a API do **URLScan.io**. Executa uma varredura de segurança na URL alvo, identificando comportamentos de phishing ou scripts maliciosos sem que o usuário precise acessar o link.

**Sintaxe:**

```text
/urlscan <url>
```

### 3.4 Integração VirusTotal (`/virustotal`)

Consulta direta à base do VirusTotal para análise de arquivos e URLs contra mais de 70 engines de antivírus.

**Sintaxe:**

```text
/virustotal <hash/url/ip>
```

### 3.5 Reputação de IP (`/ipcheck`)

Verifica a reputação de endereços IP baseando-se no **AbuseIPDB**, retornando histórico de reportes (Brute Force, SSH Abuse, etc.).

**Sintaxe:**

```text
/ipcheck <ip>
```

-----

## 4\. Monitoramento e Feeds de Inteligência

O Sheep Bot atua como um agregador de notícias e indicadores em tempo real.

### 4.1 Fontes de Dados

O sistema monitora continuamente:

  * **Feeds RSS (15 Fontes):** Agregação de portais como *The Hacker News, Bleeping Computer, Krebs on Security, CISA Alerts*.
  * **Feeds de IOCs (AlienVault OTX):** Monitoramento de 4 categorias principais:
      * Malware & Botnets
      * Phishing Campaigns
      * C2 Servers (Command & Control)
      * Ransomware Indicators

### 4.2 Configuração de Canais

Para receber as atualizações automáticas em seu servidor, utilize os comandos de configuração abaixo. Requer permissões de administrador.

  * **`/rssfeed`**: Configura o canal atual para receber notícias de cibersegurança.
  * **`/iocfeed`**: Configura o canal atual para receber alertas de novos Indicadores de Compromisso.

### 4.3 Status do Sistema

  * **`/rss_status`**: Verifica o status de conectividade dos feeds de notícias.
  * **`/ioc_status`**: Verifica o status dos feeds de ameaças.

-----

## 5\. Reconhecimento e Scanning

### 5.1 Intelligence de Hosts (`/shodan`)

Consulta a base de dados do Shodan para *passive reconnaissance*. Identifica serviços expostos, vulnerabilidades e informações de banner.

**Sintaxe:**

```text
/shodan <query>
```

### 5.2 Port Scanning (`/portscan`)

Scanner ativo de portas em tempo real (Nmap + Python).
*Nota: Uso exclusivo para membros Black Sheep (Full Access) ou limitado na versão gratuita.*

**Sintaxe:**

```text
/portscan <target> [ports]
```

-----

## 6\. Operações e Workflows

### 6.1 Workflows Padronizados (`/workflow`)

Gera templates de procedimentos baseados em frameworks de mercado (NIST/SANS) para guiar o analista.

**Tipos:**

  * `incident_response`
  * `threat_hunting`
  * `vulnerability_assessment`

**Sintaxe:**

```text
/workflow <tipo>
```

### 6.2 Resposta a Incidentes (`/incident_response`)

Gera planos de ação automatizados com base na severidade e tipo do incidente (Malware, Breach, Phishing, APT). Inclui escalonamento e gestão de timeline.

**Sintaxe:**

```text
/incident_response <tipo> <severidade>
```

*Exemplo:* `/incident_response breach critical`

-----

## 7\. Administração de Servidor (Staff)

Comandos utilitários para moderação e configuração do bot no servidor. Requer permissão de *Staff* ou *Administrator*.

  * **`/config`**: Painel de configurações gerais do bot.
  * **`/clear <quantidade>`**: Remove mensagens em massa do canal (Bulk Delete).
  * **`/kick <user> [motivo]`**: Expulsa um usuário do servidor.
  * **`/ban <user> [motivo]`**: Bane um usuário do servidor.

-----

## 8\. Licenciamento (Black Sheep)

O sistema "Black Sheep Membership" oferece acesso premium e remoção de limites.

**Benefícios:**

  * Rate limiting inteligente/expandido.
  * Acesso total ao `/portscan`.
  * Ferramentas ilimitadas (mensal).

**Comandos:**

  * **`/membership`**: Verifica o status da assinatura.
  * **`/redeem <code>`**: Resgata um código de ativação Black Sheep.

-----

**Aviso Legal:** O desenvolvedor não se responsabiliza pelo uso indevido das ferramentas de scanning. Todas as análises devem ser realizadas em alvos autorizados.
